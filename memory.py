import idc
import idaapi
import struct
from typing import *

FMT_TO_SIZE = {
	'b' : 1,
	'h' : 2,
	'i' : 4,
	'l' : 4,
	'q' : 8,
}

IS_64BIT = idaapi.get_inf_structure().is_64bit()
STR_MAXLEN = 10000

class Pointer:
	''' Represents an address. '''

	# INIT	
	def __init__(self, addr: int):
		assert type(addr) is int, 'addr can only be int!'
		self.addr = addr

	# READ/WRITE
	def read(self, size: int, offset: int = 0) -> bytes :
		''' Read bytes. '''
		return idc.get_bytes(self.addr + offset, size, True)

	def write(self, bytes: bytes, offset: int = 0) -> bool:
		''' Write bytes. '''
		return idc.write_dbg_memory(self.addr + offset, bytes) == len(bytes)

	def read_write_with_struct(self, format: str, value: int = None):
		''' R/W as integer. '''
		if value is None:
			return struct.unpack(format, self.read(FMT_TO_SIZE[format.lower()]))[0]
		else:
			return self.write(struct.pack(format, value))
	
	def u8(self, value: int = None) -> int:
		return self.read_write_with_struct('B', value)
	
	def u16(self, value: int = None) -> int:
		return self.read_write_with_struct('H', value)

	def u32(self, value: int = None) -> int:
		return self.read_write_with_struct('I', value)

	def u64(self, value: int = None) -> int:
		return self.read_write_with_struct('Q', value)

	def s8(self, value: int = None) -> int:
		return self.read_write_with_struct('b', value)

	def s16(self, value: int = None) -> int:
		return self.read_write_with_struct('h', value)

	def s32(self, value: int = None) -> int:
		return self.read_write_with_struct('u', value)

	def s64(self, value: int = None) -> int:
		return self.read_write_with_struct('q', value)

	def string(self, value: str = None, encoding: str = 'utf-8', read_length: int = None) -> str:
		''' R/W as string. '''
		# read
		if value is None:
			if read_length is not None:
				return self.read(read_length).decode(encoding)
			# read null-terminated
			string = b''
			while True:
				string += self.read(1, len(string))
				if string[-1] == b'\x00' or len(string) > STR_MAXLEN: break
			return string.decode(encoding)
		# write
		else:
			self.write(value.encode(encoding))

	def ptr(self, value: 'Pointer' = None) -> 'Pointer':
		''' R/W as pointer to pointer. '''
		method = self.u64 if IS_64BIT else self.u32
		# read
		if value is None:
			return Pointer(method())
		# write
		else:
			method(value.addr)

	# OPERATORS
	def __add__(self, other) -> 'Pointer':
		if type(other) is Pointer:
			other = other.addr
		return Pointer(self.addr + other)

	def __sub__(self, other) -> 'Pointer':
		if type(other) is Pointer:
			other = other.addr
		return Pointer(self.addr - other)

	def __eq__(self, other) -> 'Pointer':
		if type(other) is Pointer:
			other = other.addr
		return self.addr == other

	def __repr__(self):
		return f'<Pointer addr = {hex(self.addr)}>'