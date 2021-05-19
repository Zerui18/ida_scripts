import idaapi

# Keeping these allows us to use imports without the module name prefix,
# while still getting the modules to be refreshed properly.
from memory import *
from module import *
from misc import *

idaapi.require('memory')
idaapi.require('module')
idaapi.require('misc')