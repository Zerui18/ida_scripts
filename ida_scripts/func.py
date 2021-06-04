''' Provides class(es) for interacting with functions. '''

try:
	import idautils
	import ida_funcs
	import ida_name
	import idaapi
	import ida_hexrays
	import ida_lines
	import ida_pro
	import networkx as nx
except: pass
from typing import *
from .utils import *
from .struc import *

@auto_repr(['op', 'address'], { 'id' : hex, 'address' : hex })
class CItem:
	''' Represent an item inside a graph of a decompiled function. '''

	def __init__(self, item: 'ida_hexrays.citem_t', graph: nx.DiGraph):
		''' Initialise with a `ida_hexrays.citem_t` object. '''
		self.item = item
		# python can handle retain cycles
		self.graph = graph

	@property
	def id(self) -> int:
		''' Item object id. '''
		return self.item.obj_id

	@property
	def address(self) -> int:
		''' Item address. '''
		return self.item.ea

	@property
	def op(self) -> str:
		''' Name of the operation represented by this item. '''
		return ida_hexrays.get_ctype_name(self.op_id)

	@property
	def op_id(self) -> int:
		''' The operation represented by this item. '''
		return self.item.op

	@property
	def type_name(self) -> str:
		''' The name of the type associated with this item. '''
		expr: ida_hexrays.cexpr_t = self.item.cexpr
		if self.item.is_expr() and not expr.type.empty():
			tstr = expr.type._print()
			return tstr

	@property
	def accessed_struct(self) -> StrucT:
		''' Find and return the `StrucT` accessed by this memptr/memref operation. '''
		assert self.op_id in [ida_hexrays.cot_memptr, ida_hexrays.cot_memref], 'Op is not memptr or memref.'
		struct_tinfo = self.item.cexpr.x.type.get_pointed_object()
		return StrucT.find_struc(str(struct_tinfo))

	@property
	def accessed_struct_member(self) -> MemberT:
		''' Find and return the `MemberT` accessed by this memptr/memref operation. '''
		assert self.op_id in [ida_hexrays.cot_memptr, ida_hexrays.cot_memref], 'Op is not memptr or memref.'
		struct_tinfo = self.item.cexpr.x.type.get_pointed_object()
		member_offset = self.item.cexpr.m
		return StrucT.find_struc(str(struct_tinfo)).member_at_offset(member_offset)

	@property
	def called_function(self) -> 'Func':
		''' Find and return the `Func` called by this call operation. '''
		assert self.op_id in [ida_hexrays.cot_call], 'Op is not call!'
		return Func.func_at(self.item.x.obj_ea)

	@property
	def num_value(self) -> int:
		''' Return the value corresponding to this num operation. '''
		assert self.op_id in [ida_hexrays.cot_num], 'Op is not num!'
		return self.item.n._value

	# @property
	# def is_member_defined_in_struct(self) -> bool:
	# 	''' Checks whether there exists a member in the referenced struct type starting at the offset. '''
	# 	return self.accessed_struct.member_starting_at_offset(self.item.cexpr.m) is not None

	@property
	def label(self) -> str:
		''' Short label for item. '''
	
		def get_expr_name(expr):
			name = expr.print1(None)
			name = ida_lines.tag_remove(name)
			name = ida_pro.str2user(name)
			return name
		
		op = self.item.op
		insn = self.item.cinsn
		expr = self.item.cexpr
		parts = [ida_hexrays.get_ctype_name(op)]
		if op == ida_hexrays.cot_ptr:
			parts.append(".%d" % expr.ptrsize)
		elif op == ida_hexrays.cot_memptr:
			parts.append(".%d (m=%d)" % (expr.ptrsize, expr.m))
		elif op == ida_hexrays.cot_memref:
			parts.append(" (m=%d)" % (expr.m,))
		elif op in [
				ida_hexrays.cot_obj,
				ida_hexrays.cot_var]:
			name = get_expr_name(expr)
			parts.append(".%d %s" % (expr.refwidth, name))
		elif op in [
				ida_hexrays.cot_num,
				ida_hexrays.cot_helper,
				ida_hexrays.cot_str]:
			name = get_expr_name(expr)
			parts.append(" %s" % (name,))
		elif op == ida_hexrays.cit_goto:
			parts.append(" LABEL_%d" % insn.cgoto.label_num)
		elif op == ida_hexrays.cit_asm:
			parts.append("<asm statements; unsupported ATM>")
		if self.item.is_expr() and not expr.type.empty():
			tstr = expr.type._print()
			parts.append(tstr if tstr else "?")
		return "//".join(parts)

	@property
	def children(self) -> List['CItem']:
		''' The children of this item. '''
		return list(self.graph.successors(self))
	
	@property
	def n_children(self) -> int:
		''' The number of children of this item. '''
		return len(self.children)

	@property
	def parent(self) -> 'CItem':
		''' The parent of this item. '''
		return next(self.graph.predecessors(self))

	@property
	def parent_expression(self) -> 'CItem':
		''' Find and return the parent expression. '''
		node = self.parent
		while node:
			if node.op == 'expr':
				return node
			node = node.parent

	def child_where(self, condition: Callable[['CItem'], bool]) -> 'CItem':
		''' Preorder dfs search for the first child meeting the condition. '''
		dfs = nx.dfs_preorder_nodes(self.graph, self)
		node = next(dfs)
		while node:
			if condition(node):
				return node
			try:
				node = next(dfs)
			except:
				break

	def children_where(self, condition: Callable[['CItem'], bool]) -> List['CItem']:
		''' Preorder dfs search for all children meeting the condition. '''
		dfs = nx.dfs_preorder_nodes(self.graph, self)
		nodes = []
		node = next(dfs)
		while node:
			if condition(node):
				nodes.append(node)
			try:
				node = next(dfs)
			except:
				break
		return nodes

	def subtree_search_strict(self, query: Dict[str, Any]) -> List[List[List['CItem']]]:
		''' Perform a dfs tree search with the specified query.
		
		The query is a `dict` representing a subtree to search for, recursively defined as:
		```
		<query> = {
			"op" : <str>,
			"condition" : <lambda (CItem) -> bool>,
			"children" : [<query>, ...]
		}
		```

		`op` the name of the operation for the current item
		`condition` the matching condition for the current item
		`children` nested query(ies) specifying the children to match

		All fields are optional, but at least one of `op, condition` must be present.
		The query does not have to specify the complete subtree, but each of its specified level must be complete.
		ie. If node A has children B, C, query can either not specify A's children at all or it must specify A's children as both B and C.

		Returns results as a list of `List[List[CItem]]`, the outermost list representing the unique matches, each inner `List[List[CItem]]` representing a match.
		Example of a match:
		Query: `{ op : A, children: [{ op : B}, { op : C }]}`
		A Match: `[[A], [B, C]]`
		'''

		results = []

		def recursive_search(item: CItem, query: Dict[str, Any], result: List[List[CItem]] = None, index: int = 0) -> bool:
			assert 'condition' in query or 'op' in query, 'Query must have at least one of condition or op!'
			nonlocal results

			if index == 0:
				result = [[]]

			match = True
			# 1. check condition, if exists
			if 'condition' in query:
				match = match and query['condition'](item)
			# 2. check each of the other attributes
			attrs = { 'op' }
			for attr in attrs:
				if attr in query:
					match = match and query[attr] == getattr(item, attr)

			# always try to match deeper subtrees
			if index == 0:
				for child in item.children:
					recursive_search(child, query, None, 0)

			if match:
				# this node matches, search subtree
				subtree_match = False
				# add this item to the appropriate position
				if index == len(result):
					result.append([item])
				else:
					result[index].append(item)
				# this item matches, try to match children 'strictly'
				if item.n_children == 0 or not 'children' in query:
					# reached end of search
					# success if query has on more children
					subtree_match = not 'children' in query
				else:
					# needs to search deeper
					children = item.children
					if len(children) == len(query['children']):					
						for child_query in query['children']:
							for child_item in item.children:
								if recursive_search(child_item, child_query, result, index+1):
									children.remove(child_item)
									break

						if len(children) == 0:
							# queries 1-1 matched
							subtree_match = True
				if subtree_match and index == 0:
					results.append(result)
				return subtree_match
			
			# else this node doesn't match
			return False

		recursive_search(self, query)
		return results


	def __hash__(self):
		return self.item.obj_id

	def __eq__(self, other: 'CItem'):
		return hash(self) == hash(other)

class GraphBuilder(ida_hexrays.ctree_parentee_t):
	''' Utility class used to build the decompiled items graph. '''

	def __init__(self):
		ida_hexrays.ctree_parentee_t.__init__(self)
		self.graph = nx.DiGraph()
	
	def add_item(self, item: 'ida_hexrays.citem_t', type: str):
		parent = self.parents.back()
		item = CItem(item, self.graph)
		self.graph.add_node(item, type=type)
		if parent:
			self.graph.add_edge(CItem(parent, self.graph), item)
		return 0

	def visit_insn(self, i: 'ida_hexrays.cinsn_t'):
		return self.add_item(i, 'insn')

	def visit_expr(self, e: 'ida_hexrays.cexpr_t'):
		return self.add_item(e, 'expr')

@auto_repr(['original'])
class CFunc:
	''' Represent a decompiled function. '''

	def __init__(self, original: 'Func', decompiled: 'ida_hexrays.cfunc_t'):
		''' Initialise with the original `Func` and the decompiled `ida_hexrays.cfunc_t` object. '''
		self.original = original
		''' The `Func` object from which this object is derived. '''
		self.decompiled = decompiled
		''' The decompiled `ida_hexrays.cfunc_t` object. '''
		# build graph
		gb = GraphBuilder()
		gb.apply_to(decompiled.body, None)
		self.body: nx.DiGraph = gb.graph
		''' The graph representing the decompiled function. '''
		self.body_root: CItem = next(nx.topological_sort(self.body))
		''' The root node of the graph for this function. '''
	
	@property
	def psuedocode(self) -> str:
		''' Psuedocode of the decompiled function. '''
		lines = self.decompiled.get_pseudocode()
		return '\n'.join([ida_lines.tag_remove(l.line) for l in lines])


@auto_repr(['name', 'start', 'end', 'size'], { 'start' : hex, 'end' : hex, 'size' : hex})
class Func:
	''' Represent a function. '''

	@staticmethod
	def find_func(name: str) -> 'Func':
		''' Find function by name. '''
		for addr in idautils.Functions():
			if ida_name.get_ea_name(addr) == name:
				func = idaapi.get_func(addr)
				return Func(func) if func else None

	@staticmethod
	def func_at(addr: Union[Pointer, int]) -> 'Func':
		if type(addr) is Pointer:
			addr = addr.addr
		return Func(idaapi.get_func(addr))

	def __init__(self, func: 'ida_funcs.func_t'):
		''' Initialise with a `ida_funcs.func_t` object.'''
		assert type(func) is ida_funcs.func_t, 'Invalid func!'
		self.func = func

	@property
	def name(self) -> str:
		''' Function name. '''
		return ida_name.get_ea_name(self.func.start_ea)

	@property
	def start(self) -> int:
		''' Function start address. '''
		return self.func.start_ea

	@property
	def end(self) -> int:
		''' Function end address. '''
		return self.func.end_ea

	@property
	def size(self) -> int:
		''' Function size. '''
		return self.func.size()

	def decompile(self) -> CFunc:
		''' Decompile this function. '''
		err = ida_hexrays.hexrays_failure_t()
		cfunc = ida_hexrays.decompile_func(self.func, err)
		assert cfunc, f'Decompilation failed: {err}'
		return CFunc(self, cfunc)