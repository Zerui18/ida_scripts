import idc
from typing import *

from utils import *

@auto_repr(['name', 'addr'], { 'addr' : hex })
class Module:
	''' Represents a single module. '''

	@staticmethod
	def all_modules() -> List['Module']:
		''' Return a list of all the modules. '''
		m = idc.get_first_module()
		modules = []
		while m:
			modules.append(m)
			m = idc.get_next_module(m)
		return modules

	@staticmethod
	def find_module(name: str) -> 'Module':
		modules = Module.all_modules()
		for module in modules:
			if module.name.endswith(name):
				return module

	def __init__(self, addr: int):
		self.name = idc.get_module_name(addr)
		self.addr = addr

	# def __repr__(self):
	# 	return f'<Module name={self.name}, addr={hex(self.addr)}>'