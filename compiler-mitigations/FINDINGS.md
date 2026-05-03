# Compiler Mitigation Benchmark Findings

## Environment
- System: WSL2 Ubuntu 24.04, kernel 6.6.87.2
- Compiler: GCC (Ubuntu)
- ASLR: FULL (2) — stack, mmap, and heap randomised

## Binary Properties

| Binary              | PIE | CANARY | RELRO |
|---------------------|-----|--------|-------|
| No mitigations      | NO  | NO     | NO    |
| Canary only         | NO  | YES    | NO    |
| PIE only            | YES | NO     | NO    |
| Full RELRO          | NO  | NO     | YES   |
| All mitigations     | YES | YES    | YES   |

## Stack Overflow Results (100-byte input into 64-byte buffer)

| Binary              | Result  | Detail                        |
|---------------------|---------|-------------------------------|
| No mitigations      | CRASHED | Segfault (exit 139)           |
| Canary only         | BLOCKED | "stack smashing detected"     |
| PIE only            | CRASHED | Segfault (exit 139)           |
| Full RELRO          | CRASHED | Segfault (exit 139)           |
| All mitigations     | BLOCKED | "stack smashing detected"     |

Key finding: only the stack canary blocks buffer overflows. PIE and
RELRO alone do not prevent the overflow — they make exploitation
harder but the crash still occurs uncontrolled. The canary is the
only mitigation that converts an exploitable crash into a
deliberate, controlled abort.

## Format String Results (%x.%x.%x.%x)

All binaries including full mitigations: LEAKED stack values.

Key finding: FORTIFY_SOURCE=2 does not protect against format string
vulnerabilities. It adds bounds checking to buffer functions (strcpy,
sprintf) but cannot prevent printf from reading stack memory when
given a malicious format string. This demonstrates that mitigations
are not comprehensive — each covers a specific bug class only.

In production, format string vulnerabilities require a separate
control: never pass user input directly to printf. This is a code
review finding, not a compiler mitigation finding.

## ASLR Effectiveness

| Binary              | Result      | Detail                              |
|---------------------|-------------|-------------------------------------|
| No mitigations      | STATIC      | 0x402071 — same address every run   |
| PIE enabled         | RANDOMISED  | Different address each run          |
| All mitigations     | RANDOMISED  | Different address each run          |

Key finding: ASLR alone is insufficient. Without PIE, the binary
itself loads at a fixed address even when ASLR is enabled for the
stack and heap. An attacker can still hardcode the binary's load
address and use ROP gadgets within it. PIE extends ASLR to cover
the binary itself, making all addresses unpredictable.

## Combined Mitigation Effectiveness

| Attack Class        | No Mitigations | Canary Only | All Mitigations |
|--------------------|----------------|-------------|-----------------|
| Stack overflow      | Exploitable    | Blocked     | Blocked         |
| Format string leak  | Full leak      | Full leak   | Full leak       |
| Address guessing    | Possible       | Possible    | Hard            |
| GOT overwrite       | Possible       | Possible    | Blocked         |

## Residual Risk
Even with all mitigations enabled:
- Format string bugs still leak information
- A heap overflow (like CVE-2019-14378) is not blocked by canaries
  since it corrupts the heap not the stack
- Advanced techniques (heap grooming, ROP chains) can bypass
  individual mitigations — the full stack (seccomp + namespaces +
  capabilities + mitigations) is required for defence in depth

## Connection to Google Cloud
These mitigations are applied to QEMU in GCE production builds.
The canary prevents stack-based VM escape attempts. PIE+ASLR makes
heap overflow exploitation unreliable by randomising target addresses.
RELRO prevents GOT overwrite techniques. Together with seccomp-bpf
and namespace isolation they form the layered defence this lab
demonstrates end to end.
