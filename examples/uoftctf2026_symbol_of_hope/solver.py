import angr
import claripy

BIN = "./checker"

# -------------------------
# Project
# -------------------------
proj = angr.Project(BIN, auto_load_libs=False)

# -------------------------
# Symbolic input (42 bytes)
# -------------------------
flag = claripy.BVS("flag", 42 * 8)

state = proj.factory.full_init_state(
    stdin=flag
)

# -------------------------
# Hard constraints
# -------------------------

# No newline / carriage return (strcspn check)
for b in flag.chop(8):
    state.solver.add(b != 0x0a)
    state.solver.add(b != 0x0d)

# Printable (optional but helpful)
for b in flag.chop(8):
    state.solver.add(b >= 0x20)
    state.solver.add(b <= 0x7e)

# Flag format: uoftctf{...}
prefix = b"uoftctf{"
for i, c in enumerate(prefix):
    state.solver.add(flag.get_byte(i) == c)

state.solver.add(flag.get_byte(41) == ord('}'))

# -------------------------
# Simulation
# -------------------------
simgr = proj.factory.simulation_manager(state)

F4200 = 0x440e40
simgr.explore(find=F4200)

assert simgr.found, "Did not reach f_4200"
state = simgr.found[0]

# -------------------------
# Apply final constraint
# -------------------------

EXPECTED_ADDR = 0x441020
SIZE = 0x2a

# f_4200(arg1) → arg1 is in RDI
buf_ptr = state.regs.rdi

final_buf = state.memory.load(buf_ptr, SIZE)
expected  = state.memory.load(EXPECTED_ADDR, SIZE)

state.solver.add(final_buf == expected)

# -------------------------
# Solve
# -------------------------
solution = state.solver.eval(flag, cast_to=bytes)
print("[+] FLAG:", solution)

