# Linux Kernel Security Hardening Lab

Hands-on security research lab implementing and validating five layers
of Linux kernel security controls. Each section implements a real
defensive mechanism, attempts to violate it, and documents exactly
what the kernel enforces and where the limits are.

Built as part of security research aligned with Google Cloud's
virtualisation security hardening model.

---

## Lab Structure
linux-kernel-security-lab/
├── seccomp/          — syscall surface reduction via seccomp-bpf
├── namespaces/       — process isolation via Linux namespaces
├── capabilities/     — privilege reduction via capability dropping
├── ebpf/             — real-time security monitoring via eBPF
└── compiler-mitigations/ — stack canary, ASLR, PIE, RELRO benchmarks

---

## Section 1 — seccomp-bpf Syscall Filtering

**What it does:** Installs a kernel-enforced allowlist of syscalls.
Any syscall not on the list kills the process instantly with SIGSYS.

**Result:** 93.1% attack surface reduction — 312 of 335 syscalls
blocked. All four blocked syscall tests (execve, socket, ptrace,
connect) confirmed killed by kernel with signal 31.

**Key finding:** Modern glibc uses `openat()` not `open()`. Forgetting
this in a seccomp policy kills your own process. Always test policies
against real workloads.

**Security relevance:** An attacker who gains code execution in a
seccomp-filtered process cannot launch a shell, open sockets, or
inspect other processes — even with arbitrary code execution.

---

## Section 2 — Linux Namespace Isolation

**What it does:** Wraps processes in isolated views of system
resources — separate process trees, network stacks, hostnames,
and user ID spaces.

**Results:**
- PID namespace: process isolated from host process tree ✅
- UTS namespace: hostname change contained to namespace ✅
- User namespace: UID 0 inside maps to UID 1000 outside,
  /etc/shadow access denied ✅
- Network namespace: blocked by WSL2 kernel config (documented)

**Key finding:** WSL2 disables unprivileged network namespace
creation — itself a security control preventing namespace-based
attacks against the Hyper-V host. The restriction demonstrates
defence-in-depth thinking at the hypervisor layer.

---

## Section 3 — Capability Dropping

**What it does:** Reduces a root process from 41 capabilities
to the minimum required, permanently removing dangerous ones
from the bounding set.

**Result:** 40 of 41 capabilities dropped. CAP_SYS_MODULE
(kernel modules), CAP_SYS_PTRACE (process inspection), and
CAP_DAC_OVERRIDE (file permission bypass) all confirmed blocked.

**Key finding:** Calling `setuid()` to drop from root silently
wipes all capabilities unless `prctl(PR_SET_KEEPCAPS, 1)` is
called first. A common real-world misconfiguration where developers
believe they kept a capability but the UID transition removed it.

Correct hardening sequence:

prctl(PR_SET_KEEPCAPS, 1)
setuid(non_root_uid)
Rebuild minimal capability set
prctl(PR_SET_KEEPCAPS, 0)


---

## Section 4 — eBPF Security Monitor

**What it does:** Attaches kernel probes that fire inside the
kernel on suspicious syscalls, streaming structured alerts to
a Python monitoring daemon.

**Result:** 4 probes attached (execve, openat, connect, ptrace).
Captured binary execution with full paths, outbound connections,
and process activity in real time.

**Interesting finding:** Background process COMM=Relay making
repeated outbound connections detected — Windows/WSL2 relay
activity not visible through standard process monitoring.

**Limitation documented:** uprobe-based file monitoring misses
processes that call openat directly without going through libc.
Production tools (Falco, Google security infra) use kernel-level
tracepoints which WSL2 disables. Tradeoff between monitoring
depth and kernel configuration requirements is documented.

---

## Section 5 — Compiler Mitigation Benchmark

**What it does:** Compiles deliberately vulnerable C programs
with different mitigation combinations and measures which attacks
each combination stops.

**Results:**

| Mitigation      | Stack Overflow | Format String | Address Guessing |
|-----------------|---------------|---------------|------------------|
| None            | Exploitable   | Full leak     | Possible         |
| Canary only     | BLOCKED       | Full leak     | Possible         |
| PIE only        | Exploitable   | Full leak     | Hard             |
| All mitigations | BLOCKED       | Full leak     | Hard             |

**Key findings:**
- Stack canary is the only mitigation that blocks stack overflows
- FORTIFY_SOURCE=2 does NOT protect against format string bugs
- ASLR alone is insufficient — without PIE the binary loads at
  a static address every run, giving attackers a reliable target
- Each mitigation covers a specific bug class — none are comprehensive

---

## Defence-in-Depth Stack

Each layer independently limits what an attacker can do after
a successful exploit:
Layer 1 — seccomp-bpf     : 93.1% of syscalls blocked
Layer 2 — namespaces      : process cannot see host resources
Layer 3 — capabilities    : 40/41 root capabilities dropped
Layer 4 — eBPF monitor    : real-time detection of suspicious activity
Layer 5 — compiler        : stack overflow blocked, addresses randomised

An attacker who escapes a VM into a QEMU process protected by
all five layers faces:

- No execve, socket, ptrace, connect (seccomp)
- No visible host processes or filesystem (namespaces)
- No ability to load kernel modules or become root (capabilities)
- Every suspicious action logged and alerted (eBPF)
- Stack exploits blocked, addresses unpredictable (compiler)

This is the hardening model applied to QEMU in Google Cloud.

---

## Environment

- OS: Ubuntu 24.04 on WSL2 kernel 6.6.87.2-microsoft-standard-WSL2
- Python: 3.12
- GCC: Ubuntu default
- bpftrace: 0.20.2
- AFL++: 4.09c

## Related Research

This lab is companion research to:
[kvm-qemu-security-research](https://github.com/Afkir-Mohamed/kvm-qemu-security-research)
— KVM/QEMU threat modeling, CVE analysis, and fuzzing

