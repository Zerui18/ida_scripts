from types import FunctionType
from typing import *

# THESE ARE INTERNAL UTILS
# -> not meant for the users

def auto_repr(properties: List[str], transforms: Dict[str, FunctionType] = {}):
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