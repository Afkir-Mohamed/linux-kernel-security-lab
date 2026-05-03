#!/bin/bash
# Compiler mitigation benchmark
# Tests each mitigation combination against our vulnerable program

VULN=vulnerable.c
RESULTS=results.txt
> $RESULTS

section() {
    echo "" | tee -a $RESULTS
    echo "============================================================" | tee -a $RESULTS
    echo "  $1" | tee -a $RESULTS
    echo "============================================================" | tee -a $RESULTS
}

test_overflow() {
    local binary=$1
    local label=$2
    # 100 A's — enough to overflow 64-byte buffer
    local payload=$(python3 -c "print('A'*100)")
    
    result=$(./$binary stack "$payload" 2>&1)
    exit_code=$?
    
    if echo "$result" | grep -q "stack smashing detected\|Aborted\|Segmentation"; then
        status="BLOCKED"
        detail=$(echo "$result" | grep -o "stack smashing detected\|Aborted\|Segmentation fault" | head -1)
    elif [ $exit_code -ne 0 ]; then
        status="CRASHED"
        detail="exit code $exit_code"
    else
        status="SURVIVED"
        detail="no mitigation triggered"
    fi
    
    printf "  %-40s %s (%s)\n" "$label" "$status" "$detail" | tee -a $RESULTS
}

test_format() {
    local binary=$1
    local label=$2
    # Format string that tries to read stack values
    result=$(./$binary format "%x.%x.%x.%x" 2>&1)
    
    if echo "$result" | grep -q "[0-9a-f]\{4,\}"; then
        status="LEAKED"
        detail="stack values visible in output"
    else
        status="CONTAINED"
        detail="no stack leak"
    fi
    
    printf "  %-40s %s (%s)\n" "$label" "$status" "$detail" | tee -a $RESULTS
}

check_aslr() {
    local binary=$1
    local label=$2
    # Run twice and compare stack addresses using format string
    addr1=$(./$binary format "%p" 2>&1 | grep -o "0x[0-9a-f]*" | head -1)
    addr2=$(./$binary format "%p" 2>&1 | grep -o "0x[0-9a-f]*" | head -1)
    
    if [ "$addr1" != "$addr2" ] && [ -n "$addr1" ]; then
        status="RANDOMISED"
        detail="$addr1 vs $addr2"
    elif [ -z "$addr1" ]; then
        status="UNKNOWN"
        detail="format string contained by other mitigation"
    else
        status="STATIC"
        detail="same address both runs: $addr1"
    fi
    
    printf "  %-40s %s (%s)\n" "$label" "$status" "$detail" | tee -a $RESULTS
}

# ── Check system ASLR setting ────────────────────────────────────────────────

section "SYSTEM ASLR STATUS"
aslr=$(cat /proc/sys/kernel/randomize_va_space)
case $aslr in
    0) echo "  ASLR: DISABLED (0)" | tee -a $RESULTS ;;
    1) echo "  ASLR: PARTIAL (1) - stack and mmap randomised" | tee -a $RESULTS ;;
    2) echo "  ASLR: FULL (2) - stack, mmap, and heap randomised" | tee -a $RESULTS ;;
esac

# ── Compile with different mitigation combinations ───────────────────────────

section "COMPILING BINARIES"

# 1. No mitigations — maximum vulnerability
gcc $VULN -o bin_no_mitigations \
    -fno-stack-protector \
    -no-pie \
    -z norelro \
    -D_FORTIFY_SOURCE=0 \
    -w 2>&1 | grep -v "^$" | head -3
echo "  Compiled: no mitigations (-fno-stack-protector -no-pie -z norelro)" | tee -a $RESULTS

# 2. Stack canary only
gcc $VULN -o bin_canary_only \
    -fstack-protector-strong \
    -no-pie \
    -z norelro \
    -w 2>&1 | grep -v "^$" | head -3
echo "  Compiled: stack canary only (-fstack-protector-strong)" | tee -a $RESULTS

# 3. PIE only (enables ASLR for the binary itself)
gcc $VULN -o bin_pie_only \
    -fno-stack-protector \
    -pie -fPIE \
    -z norelro \
    -w 2>&1 | grep -v "^$" | head -3
echo "  Compiled: PIE only (-pie -fPIE)" | tee -a $RESULTS

# 4. Full RELRO
gcc $VULN -o bin_full_relro \
    -fno-stack-protector \
    -no-pie \
    -z relro -z now \
    -w 2>&1 | grep -v "^$" | head -3
echo "  Compiled: Full RELRO (-z relro -z now)" | tee -a $RESULTS

# 5. All mitigations — production hardened
gcc $VULN -o bin_all_mitigations \
    -fstack-protector-strong \
    -pie -fPIE \
    -z relro -z now \
    -D_FORTIFY_SOURCE=2 \
    -w 2>&1 | grep -v "^$" | head -3
echo "  Compiled: ALL mitigations (production hardened)" | tee -a $RESULTS

# ── Stack overflow tests ─────────────────────────────────────────────────────

section "STACK OVERFLOW TEST (100-byte input into 64-byte buffer)"
echo "  BINARY                                   RESULT" | tee -a $RESULTS
echo "  $( printf '%0.s-' {1..57})" | tee -a $RESULTS

test_overflow bin_no_mitigations  "No mitigations"
test_overflow bin_canary_only     "Stack canary only"
test_overflow bin_pie_only        "PIE only (no canary)"
test_overflow bin_full_relro      "Full RELRO (no canary)"
test_overflow bin_all_mitigations "All mitigations"

# ── Format string tests ──────────────────────────────────────────────────────

section "FORMAT STRING TEST (%x.%x.%x.%x)"
echo "  BINARY                                   RESULT" | tee -a $RESULTS
echo "  $( printf '%0.s-' {1..57})" | tee -a $RESULTS

test_format bin_no_mitigations  "No mitigations"
test_format bin_canary_only     "Stack canary only"
test_format bin_pie_only        "PIE only"
test_format bin_full_relro      "Full RELRO"
test_format bin_all_mitigations "All mitigations (FORTIFY_SOURCE=2)"

# ── ASLR effectiveness ───────────────────────────────────────────────────────

section "ASLR EFFECTIVENESS (address randomisation between runs)"
echo "  BINARY                                   RESULT" | tee -a $RESULTS
echo "  $( printf '%0.s-' {1..57})" | tee -a $RESULTS

check_aslr bin_no_mitigations  "No mitigations (no PIE)"
check_aslr bin_pie_only        "PIE enabled (binary randomised)"
check_aslr bin_all_mitigations "All mitigations"

# ── Binary hardening summary ─────────────────────────────────────────────────

section "BINARY HARDENING PROPERTIES (checksec)"
command -v checksec >/dev/null 2>&1 || \
    pip install checksec.py --break-system-packages -q 2>/dev/null || \
    sudo apt install -y checksec -q 2>/dev/null

for bin in bin_no_mitigations bin_canary_only bin_pie_only \
           bin_full_relro bin_all_mitigations; do
    echo "" | tee -a $RESULTS
    echo "  $bin:" | tee -a $RESULTS
    if command -v checksec >/dev/null 2>&1; then
        checksec --file=$bin --format=text 2>/dev/null | \
            grep -E "RELRO|STACK|NX|PIE|FORTIFY" | \
            sed 's/^/    /' | tee -a $RESULTS
    else
        # Manual check using readelf
        pie=$(readelf -h $bin 2>/dev/null | grep "DYN" && echo "PIE" || echo "No PIE")
        relro=$(readelf -l $bin 2>/dev/null | grep -c "GNU_RELRO" && echo "RELRO" || echo "No RELRO")
        echo "    $pie | RELRO count: $relro" | tee -a $RESULTS
    fi
done

section "SUMMARY"
echo "
  Key findings:
  
  Stack canary: Blocks stack buffer overflow by detecting corruption
    before the return address is used. Most important single mitigation.
    
  PIE + ASLR: Randomises binary load address each run, making it
    impossible to hardcode addresses in exploits. Addresses change
    between runs so an attacker cannot reliably aim at specific
    functions or gadgets.
    
  Full RELRO: Makes GOT (Global Offset Table) read-only after startup.
    Prevents attackers from overwriting function pointers stored there
    — a common technique to achieve code execution after heap overflow.
    
  FORTIFY_SOURCE: Adds bounds checking to common string functions
    (strcpy, sprintf etc.) at compile time. Catches some overflows
    before they happen.
    
  All four together represent the baseline hardening Google applies
  to production binaries including QEMU in Google Cloud.
  
  Results saved to: $RESULTS
" | tee -a $RESULTS
