# Keeping these allows us to use imports without the module name prefix,
# while still getting the modules to be refreshed properly.
from ida_scripts.memory import *
from ida_scripts.module import *
from ida_scripts.struc import *
from ida_scripts.misc import *

try:
	import idaapi
	idaapi.require('utils')
	idaapi.require('memory')
	idaapi.require('module')
	idaapi.require('struc')
	idaapi.require('misc')
except: pass