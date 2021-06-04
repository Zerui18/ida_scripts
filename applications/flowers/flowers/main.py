from ida_scripts.struc import MemberT
from typing import List, Tuple
from ida_scripts.func import CFunc, Func

f_run_ins = Func.find_func('run_ins').decompile()

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

# 4. Find all member access with index and a hardcoded offset (unrecognised members)
def find_targets(func: CFunc) -> List[Tuple[MemberT, int]]:

	# search for a->b[... + <int>]
	query = {
		'op' : 'idx',
		'children' : [
			{ 
				'op' : 'memptr'
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
			},
			{
				'op' : 'num'
			}
		]
	}
	matches2 = func.body_root.subtree_search_strict(query)
	matches2 = [m[1] for m in matches2]

	matches += matches2
	
	targets = [(hex(m[1].address), m[0].accessed_struct_member, m[1].num_value) for m in matches]

	return targets

all_targets = set()

for i, func in enumerate(functions):
	targets = find_targets(func.decompile())
	print(f'[{i}] Found {len(targets)} targets for {func}.')
	all_targets.update(targets)

print(*all_targets, sep='\n')