from ida_typeinf import tinfo_t
from utils import auto_repr
import ida_typeinf
import ida_struct
from json import dumps
from typing import *

from memory import Pointer
from utils import *

@auto_repr(['id', 'name', 'dtype', 'offset', 'size'], { 'offset' : hex, 'id' : hex })
class MemberT:
	''' Represent a member of a struct type. '''

	def __init__(self, member: ida_struct.member_t):
		assert type(member) is ida_struct.member_t, 'Invalid member!'
		self.member = member

	@property
	def id(self) -> int:
		return self.member.id

	@property
	def name(self) -> str:
		return ida_struct.get_member_name(self.id)

	@property
	def dtype(self) -> tinfo_t:
		tif = ida_typeinf.tinfo_t()
		ida_struct.get_member_tinfo(tif, self.member)
		return tif

	@property
	def offset(self) -> int:
		return self.member.soff

	@property
	def size(self) -> int:
		return ida_struct.get_member_size(self.member)

	def instance_at(self, addr: Pointer):
		''' Get the value from the given address. '''
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
		''' Get the value from the struct at the given address. '''
		return self.instance_at(struct_addr + self.offset)

@auto_repr(['id', 'name', 'size'], { 'id' : hex })
class StrucT:
	''' Represent a struct type. '''

	@staticmethod
	def find_struc(name: str) -> 'StrucT':
		''' Find struct type by name. '''
		id = ida_struct.get_struc_id(name)
		return StrucT(ida_struct.get_struc(id)) if id else None

	def __init__(self, struc: ida_struct.struc_t):
		assert type(struc) is ida_struct.struc_t, 'Invalid struc!'
		self.struc = struc

	@property
	def id(self) -> int:
		return self.struc.id

	@property
	def name(self) -> str:
		return ida_struct.get_struc_name(self.id)

	@property
	def members(self) -> List['MemberT']:
		return [MemberT(m) for m in self.struc.members]

	@property
	def size(self) -> int:
		return ida_struct.get_struc_size(self.struc)

	def instance_at(self, addr: Pointer) -> 'StrucI':
		return StrucI(addr, self)
	
	def __getitem__(self, key: str) -> MemberT:
		member = ida_struct.get_member_by_name(self.struc, key)
		return MemberT(member) if member else None

class StrucI:
	''' Represent a struct instance. '''

	def __init__(self, addr: Pointer, struc_t: StrucT):
		self.addr = addr
		self.struc_t = struc_t

	@property
	def members(self) -> Dict[str, Any]:
		members = self.struc_t.members
		return { m.name: m.instance_at_struct(self.addr) for m in members }

	def __getitem__(self, key: str):
		member = self.struc_t[key]
		if not member:
			return None
		return member.instance_at_struct(self.addr)

	def __repr__(self):
		return f'<StrucI addr={self.addr} struc_t={self.struc_t} data={dumps(self.members, default=str, indent=4)}>'