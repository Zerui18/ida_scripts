''' Provides class(es) for interacting with structures (definition and instances in memory). '''

try:
	import ida_typeinf
	import ida_typeinf
	import ida_struct
except: pass
from json import dumps
from typing import *

from .memory import Pointer
from .utils import *

@auto_repr(['id', 'name', 'dtype', 'offset', 'size'], { 'offset' : hex, 'id' : hex })
class MemberT:
	''' Represent a member of a struct type. '''

	def __init__(self, member: 'ida_struct.member_t'):
		''' Init with an `ida_struct.member_t` object. '''
		assert type(member) is ida_struct.member_t, 'Invalid member!'
		self.member: 'ida_struct.member_t' = member

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
	def find_struc(name: str) -> 'StrucT':
		''' Find struct type by name. '''
		id = ida_struct.get_struc_id(name)
		return StrucT(ida_struct.get_struc(id)) if id else None

	def __init__(self, struc: 'ida_struct.struc_t'):
		''' Init with an `ida_struct.struc_t` object. '''
		assert type(struc) is ida_struct.struc_t, 'Invalid struc!'
		self.struc: 'ida_struct.struc_t' = struc

	@property
	def id(self) -> int:
		''' Struct id. '''
		return self.struc.id

	@property
	def name(self) -> str:
		''' Struct name. '''
		return ida_struct.get_struc_name(self.id)

	@property
	def members(self) -> List['MemberT']:
		''' All member types of struct. '''
		return [MemberT(m) for m in self.struc.members]

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
		return MemberT(member) if member else None

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

	def __getitem__(self, name: str):
		''' Get a member's value by its name. '''
		member = self.struc_t[name]
		if not member:
			return None
		return member.instance_at_struct(self.addr)

	def __repr__(self):
		return f'<StrucI addr={self.addr} struc_t={self.struc_t} data={dumps(self.members, default=str, indent=4)}>'