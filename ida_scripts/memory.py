'''
Provides class(es) for interacting with the debugged process's memory.
'''

try:
	import idc
	import idaapi
	IS_64BIT = idaapi.get_inf_structure().is_64bit()
except: pass
import struct
from typing import *

from .utils import *

FMT_TO_SIZE = {
	'b' : 1,
	'h' : 2,
	'i' : 4,
	'l' : 4,
	'q' : 8,
}

STR_MAXLEN = 10000

class Pointer:
	''' Represent an address.
	The `Pointer` class offers convenient access to read/write from a memory address.

	Initialisie a `Pointer` object with `Pointer(addr: int)` or the shorthand `ptr(addr: int)`.

	A `Pointer` object provides convenient functions to read/write certain data types (integers, string, pointer) to its address in memory.
	These methods take an optional `value` parameter. They read and return the value if `value` is `None`, write and return success/failure as a `bool` when `value` is not None.
	
	`Pointer` can be added/subtracted from another `Pointer` or `int` to yield a new `Pointer`.
	'''

	# INIT	
	def __init__(self, addr: int):
		''' Initalise with an address. '''
		assert type(addr) is int, 'addr can only be int!'
		self.addr = addr

	# READ/WRITE
	def read(self, size: int, offset: int = 0) -> bytes :
		''' Read bytes from `self.addr + offset` of given size. '''
		return idc.get_bytes(self.addr + offset, size, True)

	def write(self, bytes: bytes, offset: int = 0) -> bool:
		''' Write bytes to `self.addr + offset`. '''
		return idc.write_dbg_memory(self.addr + offset, bytes) == len(bytes)

	# The following methods reads when `value` is None and writes otherwise.
	def read_write_with_struct(self, format: str, value: int = None) -> Union[int, bool]:
		''' R/W as integer. '''
		if value is None:
			return struct.unpack(format, self.read(FMT_TO_SIZE[format.lower()]))[0]
		else:
			return self.write(struct.pack(format, value))
	
	def u8(self, value: int = None) -> Union[int, bool]:
		''' Read/Write uint8. '''
		return self.read_write_with_struct('B', value)
	
	def u16(self, value: int = None) -> Union[int, bool]:
		''' Read/Write uint16. '''
		return self.read_write_with_struct('H', value)

	def u32(self, value: int = None) -> Union[int, bool]:
		''' Read/Write uint32. '''
		return self.read_write_with_struct('I', value)

	def u64(self, value: int = None) -> Union[int, bool]:
		''' Read/Write uint64. '''
		return self.read_write_with_struct('Q', value)

	def s8(self, value: int = None) -> Union[int, bool]:
		''' Read/Write int8. '''
		return self.read_write_with_struct('b', value)

	def s16(self, value: int = None) -> Union[int, bool]:
		''' Read/Write int16. '''
		return self.read_write_with_struct('h', value)

	def s32(self, value: int = None) -> Union[int, bool]:
		''' Read/Write int32. '''
		return self.read_write_with_struct('i', value)

	def s64(self, value: int = None) -> Union[int, bool]:
		''' Read/Write int64. '''
		return self.read_write_with_struct('q', value)

	def string(self, value: str = None, encoding: str = 'utf-8', read_length: int = None) -> Union[str, bool]:
		''' Read/Write string, optionally specifying a custom encoding and length to read.
		
		Parameters
		----------
		value : str, default = None
			Value to be written, the function reads if it's `None`.
		encoding : str, default = 'utf-8'
			Encoding to be used for reading/writing.
		read_length : int, defualt = None
			Length to read, leave None to read until `\\0`.

		Returns
		-------
		`str` or `bool`
			Either the read string, or a bool indicating whether write succeeded.
		'''
		# read
		if value is None:
			if read_length is not None:
				return self.read(read_length).decode(encoding)
			# read null-terminated
			string = b''
			while True:
				string += self.read(1, len(string))
				if string[-1] == 0 or len(string) > STR_MAXLEN: break
			return string.decode(encoding)
		# write
		else:
			self.write(value.encode(encoding))

	def ptr(self, value: 'Pointer' = None) -> Union['Pointer', bool]:
		''' Read/Write pointer. '''
		method = self.u64 if IS_64BIT else self.u32
		# read
		if value is None:
			return Pointer(method())
		# write
		else:
			method(value.addr)

	def hexdump_str(self, len: int = 100, offset: int = 0) -> str:
		''' Generate hexdump from `self.addr + offset` of specified length. '''
		return hexdump(self.read(len, offset), start_offset=self.addr)

	def hexdump(self, len: int = 100, offset: int = 0):
		''' Print hexdump from `self.addr + offset` of specified length. '''
		print(self.hexdump_str(len, offset))

	# OPERATORS
	def __add__(self, other: Union['Pointer', int]) -> 'Pointer':
		if type(other) is Pointer:
			other = other.addr
		return Pointer(self.addr + other)

	def __sub__(self, other: Union['Pointer', int]) -> 'Pointer':
		if type(other) is Pointer:
			other = other.addr
		return Pointer(self.addr - other)

	def __eq__(self, other: Union['Pointer', int]) -> 'Pointer':
		if type(other) is Pointer:
			other = other.addr
		return self.addr == other

	# OPERATOR ALIASES
	# for chaining
	def add(self, other: Union['Pointer', int]) -> 'Pointer':
		return self + other
	
	def sub(self, other: Union['Pointer', int]) -> 'Pointer':
		return self - other

	def __repr__(self):
		return f'*{hex(self.addr)}'

def ptr(addr: int) -> Pointer:
	''' Initialise a `Pointer`. '''
	return Pointer(addr)