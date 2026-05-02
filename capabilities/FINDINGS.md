# Capability Dropping Findings

## Results
- Started with 41 capabilities (full root)
- Dropped 10 dangerous capabilities from bounding set permanently
- Reduced to UID 65534 (nobody)
- modprobe (CAP_SYS_MODULE): BLOCKED
- /etc/shadow read (CAP_DAC_OVERRIDE): BLOCKED

## Key Finding: PR_SET_KEEPCAPS behaviour
CAP_NET_BIND_SERVICE was lost despite being in the permitted set.
Root cause: calling setuid() to drop from UID 0 to non-root
automatically wipes all capabilities unless prctl(PR_SET_KEEPCAPS, 1)
is called first.

Correct hardening sequence:
  1. prctl(PR_SET_KEEPCAPS, 1)   <- tell kernel to survive UID drop
  2. setuid(non_root_uid)         <- drop to non-root
  3. Rebuild minimal cap set      <- set only what you need
  4. prctl(PR_SET_KEEPCAPS, 0)   <- disable inheritance

This is a common real-world misconfiguration — developers believe
they kept a capability but the UID transition silently removed it,
causing services to either fail or fall back to running as root.

## Defence-in-depth stack
  Layer 1 - seccomp-bpf  : 93.1% syscall surface eliminated
  Layer 2 - namespaces   : process cannot see host resources
  Layer 3 - capabilities : 40/41 capabilities dropped
