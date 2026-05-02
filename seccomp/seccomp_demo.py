#!/usr/bin/env python3
"""
seccomp-bpf demonstration and syscall surface reduction measurement.

This program installs a restrictive seccomp filter on itself, then
attempts to make blocked syscalls to demonstrate the kernel enforcement.

Security relevance: This is the same mechanism used to sandbox QEMU
and other hypervisor processes — if an attacker escapes a VM and gains
code execution in QEMU, a seccomp filter limits what syscalls they can
make even with full control of the process.
"""
import seccomp
import os
import sys
import ctypes
import subprocess

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def result(label, value, note=""):
    note_str = f"  <- {note}" if note else ""
    print(f"  {label:<35} {value}{note_str}")

# ── Section 1: Baseline syscall surface ──────────────────────────────────────

section("BASELINE SYSCALL SURFACE")

try:
    out = subprocess.check_output(
        ['ausyscall', '--dump'], stderr=subprocess.DEVNULL
    )
    total_syscalls = len(out.decode().strip().split('\n')) - 1
except Exception:
    total_syscalls = 335

result("Architecture", "x86_64")
result("Total available syscalls", total_syscalls)
result("Typical process usage", "~50-80 syscalls")
result("Attack surface before filter", f"{total_syscalls} syscalls reachable")

# ── Section 2: Define our allowlist ──────────────────────────────────────────

section("SECCOMP-BPF ALLOWLIST")

"""
openat is the modern replacement for open() — glibc uses openat for
all file operations on Linux 3.0+. This is a common mistake when
writing seccomp policies: allowing 'read' but forgetting 'openat'
means the process can't open files at all.

Lesson: always test your seccomp policy against your actual workload
before deploying — one missing syscall kills your own process.
"""

ALLOWED_SYSCALLS = [
    # Memory management
    "mmap", "munmap", "mprotect", "brk",
    # File I/O
    "read", "write", "close", "fstat",
    # openat is the modern open() — glibc uses this, not open()
    "openat",
    # Process/signal handling
    "exit", "exit_group", "rt_sigaction", "rt_sigprocmask",
    # Thread/process creation — needed for fork() test infrastructure
    "clone", "clone3", "wait4",
    # Time
    "clock_gettime", "gettimeofday",
    # Required by Python runtime
    "futex", "getrandom", "rseq",
    # Needed for /proc reads by Python internals
    "newfstatat", "lseek",
]

print(f"\n  Default action: KILL_PROCESS (unlisted syscall = instant death)")
print(f"\n  Allowed syscalls ({len(ALLOWED_SYSCALLS)}):")
for i, sc in enumerate(ALLOWED_SYSCALLS):
    print(f"    {i+1:2}. {sc}")

blocked_count = total_syscalls - len(ALLOWED_SYSCALLS)
reduction_pct = (blocked_count / total_syscalls) * 100
print(f"\n  Syscalls blocked:  {blocked_count}/{total_syscalls}")
print(f"  Attack surface reduction: {reduction_pct:.1f}%")

# ── Section 3: Install the filter ────────────────────────────────────────────

section("INSTALLING SECCOMP-BPF FILTER")

try:
    f = seccomp.SyscallFilter(defaction=seccomp.KILL_PROCESS)
    for syscall_name in ALLOWED_SYSCALLS:
        try:
            f.add_rule(seccomp.ALLOW, syscall_name)
        except Exception as e:
            print(f"  Warning: could not add {syscall_name}: {e}")
    f.load()
    print("  Filter loaded successfully - seccomp is now active")
    print("  This process can now only make the listed syscalls")
    print("  Any other syscall = immediate SIGKILL from kernel")
except Exception as e:
    print(f"  Failed to load filter: {e}")
    sys.exit(1)

# ── Section 4: Validate allowed syscalls still work ──────────────────────────

section("VALIDATING ALLOWED SYSCALLS")

try:
    fd = os.open('/dev/null', os.O_RDONLY)  # uses openat internally
    os.read(fd, 1)
    os.close(fd)
    result("openat()+read() on /dev/null", "ALLOWED", "syscall permitted")
except Exception as e:
    result("openat()+read() on /dev/null", f"FAILED: {e}")

try:
    os.write(1, b"")
    result("write() to stdout", "ALLOWED", "syscall permitted")
except Exception as e:
    result("write() to stdout", f"FAILED: {e}")

# ── Section 5: Attempt blocked syscalls ──────────────────────────────────────

section("ATTEMPTING BLOCKED SYSCALLS")

"""
We test each blocked syscall in a child process using fork() so the
parent survives to report results. The child attempts the syscall —
if the kernel kills it with SIGSYS (signal 31) the filter worked.

These are the exact syscalls an attacker needs after a successful
VM escape into QEMU:
  - execve  : launch a shell
  - socket  : open a network connection to a C2 server
  - ptrace  : inspect or modify other processes
  - connect : reach out to attacker infrastructure
"""

def test_blocked_syscall(name, fn):
    pid = os.fork()
    if pid == 0:
        try:
            fn()
            os._exit(0)   # syscall succeeded — filter gap
        except Exception:
            os._exit(1)   # Python exception before syscall
    else:
        _, status = os.waitpid(pid, 0)
        if os.WIFSIGNALED(status):
            sig = os.WTERMSIG(status)
            if sig == 31:
                result(f"{name}", "BLOCKED",
                       f"killed by kernel SIGSYS (signal 31)")
            else:
                result(f"{name}", "BLOCKED", f"killed by signal {sig}")
        elif os.WIFEXITED(status):
            code = os.WEXITSTATUS(status)
            if code == 0:
                result(f"{name}", "!! ALLOWED", "filter gap!")
            else:
                result(f"{name}", "EXCEPTION", "Python error before syscall")

print()

# execve — launch a shell
test_blocked_syscall(
    "execve() [launch shell]",
    lambda: os.execv('/bin/sh', ['/bin/sh'])
)

# socket — open a network connection
test_blocked_syscall(
    "socket() [create socket]",
    lambda: __import__('socket').socket()
)

# ptrace — inspect other processes
test_blocked_syscall(
    "ptrace() [inspect processes]",
    lambda: ctypes.CDLL("libc.so.6").ptrace(0, 0, 0, 0)
)

# connect — reach out to attacker C2 infrastructure
test_blocked_syscall(
    "connect() [reach C2 server]",
    lambda: __import__('socket').create_connection(('1.2.3.4', 80),
                                                    timeout=0.1)
)

# ── Section 6: Summary ───────────────────────────────────────────────────────

section("SUMMARY")

print(f"""
  Before filter: {total_syscalls} syscalls available to attacker
  After filter:  {len(ALLOWED_SYSCALLS)} syscalls available
  Reduction:     {reduction_pct:.1f}% of attack surface eliminated

  An attacker with code execution in this process cannot:
    x Launch a shell       (execve blocked)
    x Create sockets       (socket blocked)
    x Inspect processes    (ptrace blocked)
    x Connect to C2 server (connect blocked)

  Key lesson learned: openat vs open
    Modern glibc uses openat() not open(). Forgetting this in a
    seccomp policy kills your own process. Always test policies
    against real workloads before deploying.

  This is the same principle behind QEMU sandboxing in Google Cloud.
  Even a successful VM escape is contained by the seccomp filter.
""")
