#!/usr/bin/env python3
import subprocess
import sys
import os
import signal
from datetime import datetime

SENSITIVE_FILES = [
    '/etc/shadow', '/etc/passwd',
    '/root/.ssh', '/etc/sudoers',
]

LIBC = '/lib/x86_64-linux-gnu/libc.so.6'

BPFTRACE_PROGRAM = """
uprobe:{libc}:execve
{{
    printf("EXECVE|%d|%s|%s\\n", pid, comm, str(arg0));
}}

uprobe:{libc}:openat
{{
    printf("OPENAT|%d|%s|%s\\n", pid, comm, str(arg1));
}}

kprobe:__x64_sys_connect
{{
    printf("CONNECT|%d|%s|outbound\\n", pid, comm);
}}

kprobe:__x64_sys_ptrace
{{
    printf("PTRACE|%d|%s|request=%d\\n", pid, comm, (int64)arg0);
}}
""".format(libc=LIBC)

SEVERITY_RULES = {
    'EXECVE':  {'severity': 'HIGH',
                'reason': 'Process execution'},
    'PTRACE':  {'severity': 'CRITICAL',
                'reason': 'ptrace syscall'},
    'CONNECT': {'severity': 'MEDIUM',
                'reason': 'Outbound connection'},
    'OPENAT':  {'severity': 'LOW',
                'reason': 'File access'},
}

COLORS = {
    'CRITICAL': '\033[91m',
    'HIGH':     '\033[93m',
    'MEDIUM':   '\033[94m',
    'LOW':      '\033[92m',
}
RESET = '\033[0m'

def is_sensitive(path):
    return any(path.startswith(s) for s in SENSITIVE_FILES)

def format_alert(event_type, pid, comm, detail, timestamp):
    severity = SEVERITY_RULES[event_type]['severity']
    if event_type == 'OPENAT' and is_sensitive(detail):
        severity = 'CRITICAL'
    color = COLORS.get(severity, '')
    return (f"{color}[{severity:8}]{RESET} "
            f"{timestamp} | "
            f"PID={pid:6} COMM={comm:15} | "
            f"{event_type:7} | {detail[:60]}")

def parse_line(line):
    if not line or '|' not in line:
        return None
    parts = line.split('|', 3)
    if len(parts) < 4:
        return None
    event_type, pid, comm, detail = parts
    if event_type not in SEVERITY_RULES:
        return None
    return event_type, pid.strip(), comm.strip(), detail.strip()

stats = {k: 0 for k in
         ['EXECVE','PTRACE','CONNECT','OPENAT',
          'CRITICAL','HIGH','MEDIUM','LOW']}
_done = False

def print_stats():
    global _done
    if _done:
        return
    _done = True
    print(f"\n{'='*60}")
    print(f"  MONITOR SESSION SUMMARY")
    print(f"{'='*60}")
    for k in ['EXECVE','PTRACE','CONNECT','OPENAT']:
        print(f"  {k:<10} {stats[k]}")
    print()
    for k in ['CRITICAL','HIGH','MEDIUM','LOW']:
        print(f"  {k:<10} {stats[k]}")

BORING = ['/proc','/sys','/dev','/usr/lib',
          '/usr/share','/run','/var/lib','/lib']

def is_boring(event_type, detail):
    if event_type != 'OPENAT':
        return False
    if not detail or detail.isdigit() or len(detail) < 2:
        return True
    return any(detail.startswith(b) for b in BORING)

def main():
    print(f"\n{'='*60}")
    print(f"  eBPF SECURITY MONITOR")
    print(f"{'='*60}")
    print(f"  Mode: uprobes (libc) + kprobes (kernel)")
    print(f"  Monitoring: execve, openat, connect, ptrace")
    print(f"  Press Ctrl+C to stop\n")

    prog_path = '/tmp/monitor.bt'
    with open(prog_path, 'w') as f:
        f.write(BPFTRACE_PROGRAM)

    proc = subprocess.Popen(
        ['sudo', 'bpftrace', prog_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0
    )

    def cleanup(signum=None, frame=None):
        proc.terminate()
        print_stats()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)

    try:
        while True:
            raw = proc.stdout.readline()
            if not raw:
                break
            line = raw.decode('utf-8', errors='replace').strip()
            if not line:
                continue
            if 'Attaching' in line:
                print(f"  [bpftrace] {line}")
                continue
            if 'ERROR' in line:
                print(f"  [ERROR] {line}")
                continue
            if 'WARNING' in line:
                continue

            parsed = parse_line(line)
            if not parsed:
                continue

            event_type, pid, comm, detail = parsed
            if is_boring(event_type, detail):
                continue

            stats[event_type] += 1
            severity = SEVERITY_RULES[event_type]['severity']
            if event_type == 'OPENAT' and is_sensitive(detail):
                severity = 'CRITICAL'
            if severity in stats:
                stats[severity] += 1

            ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            print(format_alert(event_type, pid, comm, detail, ts))
            sys.stdout.flush()

    except Exception as e:
        print(f"Error: {e}")
    finally:
        print_stats()

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("Run with: sudo python3 ebpf/security_monitor.py")
        sys.exit(1)
    main()
