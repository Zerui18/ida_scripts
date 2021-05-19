import ida_frame
import ida_struct
import idaapi
import idc
from memory import Pointer

def find_local_var(var_name, size=4) -> Pointer:
	if size < 1:
		return None
	frame = ida_frame.get_frame(idc.here())
	loc_var = ida_struct.get_member_by_name(frame, var_name)
	if (loc_var is None):
		return None
	stack_ptr = idc.GetRegValue('rsp' if idaapi.get_inf_structure().is_64bit() else 'esp')
	ea = loc_var.soff + stack_ptr
	return Pointer(ea)

def find_symbol(name: str) -> Pointer:
	addr = idc.get_name_ea_simple(name)
	print(addr)
	if addr == idc.BADADDR:
		return None
	return Pointer(addr)