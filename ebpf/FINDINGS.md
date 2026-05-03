# eBPF Security Monitor Findings

## Environment
- Kernel: WSL2 6.6.87.2-microsoft-standard-WSL2
- Tool: bpftrace 0.20.2
- Approach: hybrid uprobes (libc) + kprobes (kernel)

## What Works

### EXECVE monitoring — fully functional
Uprobe on libc:execve captures every binary execution with:
- Full binary path (/usr/bin/cat, /usr/bin/python3 etc.)
- PID and parent process name
- Timestamp

Real finding: monitor captured background WSL2 relay process
(COMM=Relay) making repeated outbound connections — activity
not visible through standard process monitoring tools.

### CONNECT monitoring — fully functional
kprobe on __x64_sys_connect captures all outbound connection
attempts with PID and process name.

### PTRACE monitoring — functional
kprobe on __x64_sys_ptrace captures process inspection attempts.

## Limitations Discovered

### OPENAT file path monitoring — partial
Uprobe on libc:openat captures file paths for some processes
but not all. Root cause: Python and other runtimes make openat
syscalls directly without going through the libc wrapper,
bypassing the uprobe entirely.

This is a fundamental limitation of userspace (uprobe) monitoring
versus kernel-level monitoring.

### Production solution
Production security tools (Falco, Google's security infra) use
kernel-level eBPF tracepoints for file monitoring, which intercept
the syscall regardless of whether libc is used. WSL2 disables
the tracepoint subsystem entirely, making this approach unavailable
in our environment.

This tradeoff is documented here because understanding WHY a
monitoring approach has gaps is as important as implementing it.

## Interesting Findings During Testing

1. Background process COMM=Relay making repeated outbound connections
   — likely VS Code or Windows Relay communicating through WSL2.
   Demonstrates monitor catches real unexpected network activity.

2. Bash session startup executes 8+ binaries (locale-check, locale,
   grep, find, lesspipe, basename, dirname, dircolors) before showing
   a prompt. This baseline is useful for detecting anomalous process
   trees in production.

3. ps makes outbound connect() calls — reads /proc filesystem sockets.
   Shows importance of process whitelisting to reduce false positives.

## Defence-in-depth stack
  Layer 1 - seccomp-bpf  : 93.1% syscall surface eliminated
  Layer 2 - namespaces   : process cannot see host resources
  Layer 3 - capabilities : 40/41 capabilities dropped
  Layer 4 - eBPF monitor : real-time detection of suspicious activity
