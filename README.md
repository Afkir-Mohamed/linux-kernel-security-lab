# Linux Kernel Security Hardening Lab

Hands-on research lab implementing and validating layered kernel security 
controls on a live Linux system. Each section implements a control, 
attempts to violate it, and documents what the kernel mechanism blocks.

## Structure
- `/seccomp`       — seccomp-bpf syscall filtering
- `/namespaces`    — Linux namespace isolation
- `/capabilities`  — capability dropping to minimal sets
- `/apparmor`      — mandatory access control profiles
- `/ebpf`          — eBPF-based security monitor
- `/compiler-mitigations` — ASLR, stack canaries, PIE, CFI benchmarks
- `/docs`          — findings and runbooks

## Research Goals
1. Reduce exploitable syscall surface by 70%+ via seccomp-bpf
2. Isolate processes using Linux namespaces
3. Drop capabilities to minimal required sets
4. Monitor anomalous syscall patterns with eBPF
5. Benchmark compiler mitigations against memory corruption test cases
