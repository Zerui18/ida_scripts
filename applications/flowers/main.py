import ida_hexrays

from ida_scripts.struc import MemberT
from typing import List, Tuple
from ida_scripts.func import CFunc, CItem, Func

f_run_ins = Func.find('run_ins').decompile()

# 1. Find ... = some function call in a switch case
query = {
	'op' : 'block',
	'children' : [
		{
			'op' : 'expr',
			'children' : [
				{
					'op' : 'asg'
				}
			]
		},
		{
			'op' : 'break'
		}
	]
}
matches = f_run_ins.body_root.subtree_search_strict(query)
assigns = [m[2][0] for m in matches]

# 2. Find the function call itself
calls = [assign.child_where(lambda c: c.op == 'call') for assign in assigns]

# 3. Find all called functions
functions = [call.called_function for call in calls]

target_struct = 'overall_state'

# 4. Find all member access with index and a hardcoded offset (unrecognised members)
def find_targets(func: CFunc) -> List[Tuple[MemberT, int]]:

	# search for a->b[... + <int>]
	query = {
		'op' : 'idx',
		'children' : [
			{ 
				'op' : 'memptr',
				'condition' : lambda item: item.accessed_struct.name == target_struct and item.accessed_struct_member.is_gap
			},
			{
				'op' : 'add',
				'condition' : lambda item: item.child_where(lambda c: c.op == 'num' and c.parent.op == 'add')
			}
		]
	}
	matches = func.body_root.subtree_search_strict(query)
	matches = [m[1] for m in matches]
	matches = [(m[0], m[1].child_where(lambda c: c.op == 'num' and c.parent.op == 'add')) for m in matches]
	
	# search for a->b[<int>]
	query = {
		'op' : 'idx',
		'children' : [
			{
				'op' : 'memptr',
				'condition' : lambda item: item.accessed_struct.name == target_struct and item.accessed_struct_member.is_gap
			},
			{
				'op' : 'num'
			}
		]
	}
	matches2 = func.body_root.subtree_search_strict(query)
	matches2 = [tuple(m[1]) for m in matches2]

	return matches + matches2

all_targets = []

for i, func in enumerate(functions):
	targets = find_targets(func.decompile())
	print(f'[{i}] Found {len(targets)} targets for {func}.')
	all_targets += targets

print(*all_targets, sep='\n')

# remove duplicates
all_targets: List[Tuple[CItem, CItem]] = list(dict.fromkeys(all_targets))

print(*all_targets, sep='\n')
print(f'total {len(all_targets)} to be inserted')

TYPE_MAPPING = {
	'_BYTE' : 'char',
	'_DWORD': 'int'
}

params = []

for memptr, num in all_targets:
	print(memptr)
	cast = memptr.parent_where(lambda p: p.op == 'cast')
	if cast:
		if cast.parent.op == 'ptr':
			# pointer dereferenced, use dereferenced type
			print(memptr, cast, cast.parent, cast.parent.type_name)
			type = cast.parent.type_name
		else:
			# still pointer, use cast's type
			print(memptr, cast, cast.type_name)
			type = cast.type_name
	else:
		# no cast, use idx's type (which should be char since they're all gaps)
		print(memptr, memptr.parent.type_name)
		type = memptr.parent.type_name
	if type in TYPE_MAPPING:
		type = TYPE_MAPPING[type]
	print(memptr)
	member = memptr.accessed_struct_member
	struct = member.struct
	offset = num.num_value + member.offset
	member_name = f'{type.split()[0]}{hex(offset)[2:].upper()}'
	params.append((type, member_name, offset))

for type, name, offset in params:
	try:
		member = struct.add_member_auto(f'{type} {name}', offset)
		offset = hex(offset)
		if member:
			print('Added member:', name)
		else:
			print('Failed:', type, name, offset)
	except Exception as e:
		print('Failed:', type, name, offset, e)