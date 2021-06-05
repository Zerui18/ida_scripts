from types import MethodType
from typing import *
import json

# THESE ARE INTERNAL UTILS
# -> not meant for the users

def auto_repr(properties: List[str], transforms: Dict[str, Callable] = {}):
	''' Automatically generate __repr__ from a list of properties, optionally specifying transforms. '''
	def decorator(cls):
		def repr(self):
			# perform transform if specified
			maybe_transform = lambda p, value: transforms[p](value) if p in transforms else value
			props = [f'{p}={maybe_transform(p, getattr(self, p))}' for p in properties]
			props = ', '.join(props)
			return f'<{cls.__name__} {props}>'
		cls.__repr__ = repr
		return cls
	return decorator

def hexdump(data, length = 16, sep = '.', start_offset = 0):
	result = []

	for i in range(0, len(data), length):
		subSrc = data[i:i+length]
		hexa = ''
		for h in range(0,len(subSrc)):
			if h == length/2:
				hexa += ' '
			h = subSrc[h]
			if not isinstance(h, int):
				h = ord(h)
			h = hex(h).replace('0x','')
			if len(h) == 1:
				h = '0'+h
			hexa += h+' '
		hexa = hexa.strip(' ')
		text = ''
		for c in subSrc:
			if not isinstance(c, int):
				c = ord(c)
			if 0x20 <= c < 0x7F:
				text += chr(c)
			else:
				text += sep
		result.append(('%08X:  %-'+str(length*(2+1)+1)+'s  |%s|') % (i + start_offset, hexa, text))

	return '\n'.join(result)

def to_hex(n: int) -> str:
	return hex(n)[2:].upper()

def get_properties(obj: object) -> Dict[str, Any]:
	attrs = {}
	for attr in dir(obj):
		try:
			val = getattr(obj, attr)
			if not callable(val):
				attrs[attr] = val
		except Exception as e:
			attrs[attr] = f'[Failed] {e}'
	return attrs

def print_properties(obj: object):
	print(json.dumps(get_properties(obj), indent=4, default=str))

pp = print_properties

STRUC_ERROR_MEMBER_DESCRIPTIONS = {
	-1 : 'already has member with this name (bad name)',
	-2 : 'already has member at this offset',
	-3 : 'bad number of bytes or bad sizeof(type)',
	-4 : 'bad typeid parameter',
	-5 : 'bad struct id (the 1st argument)',
	-6 : 'unions can\'t have variable sized members',
	-7 : 'variable sized member should be the last member in the structure',
	-8 : 'recursive structure nesting is forbidden',
}