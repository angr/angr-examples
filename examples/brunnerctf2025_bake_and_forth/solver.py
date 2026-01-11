import angr
import logging
logging.getLogger('angr').setLevel('DEBUG')
proj = angr.Project("./bake_and_forth", support_selfmodifying_code=True)

simgr = proj.factory.simgr()
simgr.explore(find=lambda s: "CORRECT!".encode() in s.posix.dumps(1))

s = simgr.found[0]
flag = s.posix.dumps(0)
print(flag)
