import ida_frame
import ida_struct
import idaapi
import idc

from memory import Pointer

def find_local_var(var_name: str) -> Pointer:
	''' Find a local variable by name when paused in a function frame. '''
	frame = ida_frame.get_frame(idc.here())
	loc_var = ida_struct.get_member_by_name(frame, var_name)
	if (loc_var is None):
		return None
	stack_ptr = idc.GetRegValue('rsp' if idaapi.get_inf_structure().is_64bit() else 'esp')
	ea = loc_var.soff + stack_ptr
	return Pointer(ea)

def find_symbol(name: str) -> Pointer:
	''' Find a global symbol by name. '''
	addr = idc.get_name_ea_simple(name)
	if addr == idc.BADADDR:
		return None
	return Pointer(addr)