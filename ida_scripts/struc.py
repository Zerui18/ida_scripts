''' Provides class(es) for interacting with structures (definition and instances in memory). '''

try:
	import ida_typeinf
	import ida_struct
	import ida_idaapi
	import ida_bytes
	import idc
except: pass

import re
from json import dumps
from typing import *

from .memory import Pointer
from .utils import *

@auto_repr(['id', 'name', 'dtype', 'offset', 'size'], { 'offset' : hex, 'id' : hex })
class MemberT:
	''' Represent a member of a struct type. '''

	def __init__(self, member: 'ida_struct.member_t', struct: 'StrucT'):
		''' Init with an `ida_struct.member_t` object. '''
		assert type(member) is ida_struct.member_t, 'Invalid member!'
		self.member: 'ida_struct.member_t' = member
		self.struct = struct
		''' The struct type containing this member. '''

	@property
	def id(self) -> int:
		''' Member id (mid). '''
		return self.member.id

	@property
	def name(self) -> str:
		''' Member name. '''
		return ida_struct.get_member_name(self.id)

	@property
	def dtype(self) -> 'ida_typeinf.tinfo_t':
		''' Member type, represented with `ida_typeinf.tinfo_t`. '''
		tif = ida_typeinf.tinfo_t()
		ida_struct.get_member_tinfo(tif, self.member)
		return tif

	@property
	def offset(self) -> int:
		''' Member offset in struct. '''
		return self.member.soff

	@property
	def size(self) -> int:
		''' Member size in bytes. '''
		return ida_struct.get_member_size(self.member)

	@property
	def is_gap(self) -> bool:
		return str(self.dtype)[:4] in ['char', '_BYT'] and self.name.startswith('gap')

	def instance_at(self, addr: Pointer) -> Union[Pointer, int]:
		''' Get the value from the given address.
		
		This method reads and parses the value at the given address using the appropriate type.

		Parameters
		----------
		addr : `Pointer`

		Returns
		-------
		`Pointer` or `int`
			The parsed value.
		'''
		dtype = self.dtype
		# return ptr/array as Pointer
		if dtype.is_ptr_or_array():
			return addr
		# treat everthing else as int
		else:
			assert not dtype.is_floating(), 'FP not supported yet!'
			signed = dtype.is_signed()
			length = dtype.get_size() * 8
			method = f'{"s" if signed else "u"}{length}'
			assert hasattr(addr, method), f'Cannot find method {method}, it is likely not supported.'
			return getattr(addr, method)()

	def __hash__(self) -> int:
		return self.id

	def __eq__(self, o: object) -> bool:
		return hash(self) == hash(o)

	def instance_at_struct(self, struct_addr: Pointer):
		''' Get the value from a struct at the given address.
		
		Identical to `instance_at` but applies the offset of this member.

		Parameters
		----------
		struct_addr : `Pointer`
			A pointer to an instance of the struct.

		Returns
		-------
		`Pointer` or `int`
			The parsed value.
		'''
		return self.instance_at(struct_addr + self.offset)

@auto_repr(['id', 'name', 'size'], { 'id' : hex })
class StrucT:
	''' Represent a struct type. '''

	@staticmethod
	def find(name: str) -> 'StrucT':
		''' Find struct type by name. '''
		id = ida_struct.get_struc_id(name)
		return StrucT(ida_struct.get_struc(id)) if id != ida_idaapi.BADADDR else None

	@staticmethod
	def add_struc(name: str) -> 'StrucT':
		''' Create and return an empty struct. '''
		id = ida_struct.add_struc(ida_idaapi.BADADDR, name, False)
		return StrucT(ida_struct.get_struc(id)) if id != ida_idaapi.BADADDR else None

	def __init__(self, struc: 'ida_struct.struc_t'):
		''' Init with an `ida_struct.struc_t` object. '''
		assert type(struc) is ida_struct.struc_t, 'Invalid struc!'
		self.struc: ida_struct.struc_t = struc

	@property
	def id(self) -> int:
		''' Struct id. '''
		return self.struc.id

	@property
	def name(self) -> str:
		''' Struct name. '''
		return ida_struct.get_struc_name(self.id)

	@property
	def members(self) -> List[MemberT]:
		''' All member types of struct. '''
		return [MemberT(m, self) for m in self.struc.members]

	@property
	def size(self) -> int:
		''' Struct size in bytes. '''
		return ida_struct.get_struc_size(self.struc)

	def instance_at(self, addr: Pointer) -> 'StrucI':
		''' Get an instance of this struct at the given address. '''
		return StrucI(addr, self)
	
	def __getitem__(self, name: str) -> MemberT:
		''' Get a member type by name. '''
		member = ida_struct.get_member_by_name(self.struc, name)
		return MemberT(member, self) if member else None

	def member_at_offset(self, offset: int) -> MemberT:
		''' Get a member type by offset. '''
		member = ida_struct.get_member_by_id(ida_struct.get_member_id(self.struc, offset))
		return MemberT(member[0], self) if member else None

	def member_starting_at_offset(self, offset: int) -> bool:
		'''  Get a member type by offset, member must start at offset. '''
		member = self.member_at_offset(offset)
		return member if member and member.offset == offset else None

	# MUTATING METHODS
	# These methods do not check alignments.

	@staticmethod
	def create_struc(name: str) -> 'StrucT':
		''' Create and return a new struct with a given name. '''
		tid = ida_struct.add_struc(ida_idaapi.BADADDR, name, False)
		struct = ida_struct.get_struc(tid)
		return StrucT(struct)

	def add_member(self, declaration: str, offset: int) -> MemberT:
		''' Create and return a new member in this struct type.

		`declaration` should be like `TYPE_NAME NAME[SIZE]` (Array is optional).
		'''
		# parse decl
		tinfo, name = parse_declaration(declaration)
		size = tinfo.get_size()
		# create a bytes member of equivalent size
		result = ida_struct.add_struc_member(self.struc, name, offset, idc.FF_BYTE, None, size)
		assert result == 0, f'Failed to add member: {STRUC_ERROR_MEMBER_DESCRIPTIONS[result]}'
		member = self[name]
		# apply the correct tinfo
		ida_struct.set_member_tinfo(self.struc, member.member, 0, tinfo, 2) # SET_MEMTI_COMPATIBLE 2
		return member

	def add_gap(self, offset: int, size: int) -> MemberT:
		''' Create and return a new member representing a bytes gap. '''
		name = f'gap{to_hex(offset)}'
		return self.add_member(f'_BYTE {name}[{size}]', offset)

	def delete_member(self, member: MemberT) -> bool:
		''' Delete a given member. '''
		return ida_struct.del_struc_member(self.struc, member.offset)

	def add_member_auto(self, declaration: str, offset: int) -> MemberT:
		''' Create and return a new member in this struct type, automatically reworking gaps.

		`declaration` should be like `TYPE_NAME NAME[SIZE]` (Array is optional).

		A gap is recognised by:
		1. Is a single or array of 'char' or '_BYTE'.
		2. Name starting with 'gap' (all lowercase).

		If the requested offset falls within a gap of the above definition, the gap will automatically be adjusted to accomodate the new member.

		'''
		# check if offset's in a gap

		member = self.member_at_offset(offset)
		if member:
			# check if member's a gap
			# must be byte (one or array) with name starting with 'gap'
			assert member.is_gap, 'Failed to add member: offset is occupied by a non-gap member.'
			# recreate gap(s)
			gap_start = member.offset
			gap_end = member.offset + member.size
			# 1. delete existing gap
			assert self.delete_member(member), 'Failed to delete existing gap.'
			# 2. create lower gap if necessary
			if offset > gap_start:
				self.add_gap(gap_start, offset - gap_start)
			# 3. create member
			new_member = self.add_member(declaration, offset)
			# 4. create higher gap if necessary
			higher_gap_start = new_member.offset + new_member.size
			if higher_gap_start < gap_end:
				self.add_gap(higher_gap_start, gap_end - higher_gap_start)
			return new_member
		else:
			return self.add_member(declaration, offset)

	def __hash__(self) -> int:
		return self.id

	def __eq__(self, o: object) -> bool:
		return hash(self) == hash(o)


class StrucI:
	''' Represent a struct instance. '''

	def __init__(self, addr: Pointer, struc_t: StrucT):
		''' Init with a base address and a struct type. '''
		self.addr: Pointer = addr
		''' The address of this struct. '''
		self.struc_t: StrucT = struc_t
		''' The type definition of this struct. '''

	@property
	def members(self) -> Dict[str, Any]:
		''' Collect all members of this struct as a dict. '''
		members = self.struc_t.members
		return { m.name: m.instance_at_struct(self.addr) for m in members }

	def member(self, name: str, return_pointer: bool = True):
		''' Get a member's value or `Pointer` by its name. '''
		member = self.struc_t[name]
		if not member:
			return None
		return self.addr + member.offset if return_pointer else member.instance_at_struct(self.addr)

	def __getitem__(self, name: str):
		''' Get a member's value by its name. '''
		return self.member(name)

	def __setitem__(self, name: str, value) -> bool:
		''' Set a member's value by its name. '''
		member_ptr: Pointer = self.member(name)
		assert member_ptr, f'Cannot find member {name} for struct {self.struc_t}!'
		if type(value) is str:
			member_ptr.string(value)
		# treat everthing else as int
		else:
			dtype = self.struc_t[name].dtype
			assert not dtype.is_floating(), 'FP not supported yet!'
			signed = dtype.is_signed()
			length = dtype.get_size() * 8
			method = f'{"s" if signed else "u"}{length}'
			assert hasattr(member_ptr, method), f'Cannot find accessor for {method}, it is likely not supported.'
			return getattr(member_ptr, method)(value)

	def __repr__(self):
		return f'<StrucI addr={self.addr}, struc_t={self.struc_t}, data={dumps(self.members, default=str, indent=4)}>'

	def __hash__(self) -> int:
		return hash(self.struc_t) ^ self.addr

	def __eq__(self, o: object) -> bool:
		return type(o) is StrucI and self.struc_t == o.struc_t and self.addr == o.addr

def parse_declaration(declaration):
	m = re.search(r"^(\w+[ *]+)(\w+)(\[(\d+)\])?$", declaration)
	assert m, 'Member declaration should be like `TYPE_NAME NAME[SIZE]` (Array is optional)'

	type_name, field_name, _, arr_size = m.groups()
	assert not field_name[0].isdigit(), 'Bad field name'

	result = idc.parse_decl(type_name, 0)
	assert result, 'Failed to parse member type. It should be like `TYPE_NAME NAME[SIZE]` (Array is optional)'

	_, tp, fld = result
	tinfo = ida_typeinf.tinfo_t()
	tinfo.deserialize(ida_typeinf.cvar.idati, tp, fld, None)
	if arr_size:
		assert tinfo.create_array(tinfo, int(arr_size))
	return tinfo, field_name