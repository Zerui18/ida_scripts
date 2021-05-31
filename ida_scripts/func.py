''' Provides class(es) for interacting with functions. '''

try:
	import idautils
	import ida_funcs
	import ida_name
	import idaapi
	import ida_hexrays
	import ida_lines
	import ida_pro
except: pass
from typing import *

from .utils import *

@auto_repr(['address', 'label'])
class CItem:
	''' Represent a citem inside a decompiled function. '''

	def __init__(self, item: 'ida_hexrays.citem_t'):
		''' Initialise with a `ida_hexrays.citem_t` object. '''
		self.item = item

	@property
	def address(self) -> int:
		''' Item address. '''
		return self.item.ea

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
		return " // ".join(parts)

@auto_repr(['original'])
class CFunc:
	''' Represent a decompiled function. '''

	def __init__(self, original: 'Func', decompiled: 'ida_hexrays.cfunc_t'):
		''' Initialise with the original `Func` and the decompiled `ida_hexrays.cfunc_t` object. '''
		self.original = original
		self.decompiled = decompiled
	
	@property
	def psuedocode(self) -> str:
		''' Psuedocode of the decompiled function. '''
		lines = self.decompiled.get_pseudocode()
		return '\n'.join([ida_lines.tag_remove(l.line) for l in lines])

	@property
	def items(self) -> List[CItem]:
		''' Items of the decomipled function. '''
		return [CItem(i) for i in self.decompiled.treeitems]


@auto_repr(['name', 'start', 'end', 'size'], { 'start' : hex, 'end' : hex, 'size' : hex})
class Func:
	''' Represent a function. '''

	@staticmethod
	def find_func(name: str) -> 'Func':
		''' Find function by name. '''
		for addr in idautils.Functions():
			if ida_name.get_ea_name(addr) == name:
				func = idaapi.get_func(addr)
				return Func(idaapi.get_func(addr)) if func else None

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