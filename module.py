import idc
from typing import *

class Module:
	''' Represents a single module. '''

	@staticmethod
	def all_modules() -> List[Tuple[str, int]]:
		''' Return a list of all the modules. '''
		m = idc.get_first_module()
		modules = [Module(m)]
		while True:
			m = idc.get_next_module(m)
			if m is None:
				break
			modules.append(Module(m))
		return modules

	def __init__(self, addr: int):
		self.name = idc.get_module_name(addr)
		self.faddr = addr
		self.addr = idc.get_ea

	def __repr__(self):
		return f'<{self.name} at f-off {hex(self.addr)}>'