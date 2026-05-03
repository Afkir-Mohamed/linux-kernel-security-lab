/*
 * Three deliberately vulnerable C programs used to benchmark
 * compiler mitigations.
 *
 * DO NOT run these in production. These are intentional security
 * vulnerabilities for educational/research purposes only.
 *
 * Vulnerabilities:
 *   1. Stack buffer overflow — classic overflow of a fixed stack buffer
 *   2. Format string bug — user input passed directly to printf
 *   3. Heap overflow — write past end of malloc'd buffer
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── Vulnerability 1: Stack buffer overflow ────────────────────────────── */

void vuln_stack_overflow(char *input) {
    /*
     * buf is 64 bytes on the stack.
     * strcpy does NO bounds checking — it copies until it hits \0.
     * If input is longer than 64 bytes it overwrites:
     *   - saved frame pointer (rbp)
     *   - return address (rip)
     * Overwriting rip lets an attacker redirect execution anywhere.
     *
     * Stack layout:
     *   [buf 64 bytes][canary 8 bytes][rbp 8 bytes][rip 8 bytes]
     *
     * With stack canary: overwriting canary triggers abort before rip
     * Without canary: attacker controls rip directly
     */
    char buf[64];
    strcpy(buf, input);  /* VULNERABLE: no bounds check */
    printf("Input was: %s\n", buf);
}

/* ── Vulnerability 2: Format string bug ────────────────────────────────── */

void vuln_format_string(char *input) {
    /*
     * printf with user-controlled format string.
     * An attacker can use %x to read stack values,
     * %s to read arbitrary memory, %n to write to memory.
     *
     * Example attack: "./prog '%x %x %x'" leaks stack addresses
     * This undermines ASLR by revealing where things are loaded.
     */
    printf(input);       /* VULNERABLE: user controls format string */
    printf("\n");
}

/* ── Vulnerability 3: Heap overflow ────────────────────────────────────── */

void vuln_heap_overflow(char *input) {
    /*
     * Allocates 32 bytes on the heap, copies unbounded input into it.
     * Overwrites heap allocator metadata adjacent to the buffer.
     * This is the same class as CVE-2019-14378 we analysed.
     */
    char *buf = malloc(32);
    if (!buf) return;
    strcpy(buf, input);  /* VULNERABLE: no bounds check */
    printf("Heap input: %s\n", buf);
    free(buf);
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <vuln_type> <input>\n", argv[0]);
        printf("  vuln_type: stack | format | heap\n");
        return 1;
    }

    char *type  = argv[1];
    char *input = argv[2];

    if (strcmp(type, "stack") == 0) {
        vuln_stack_overflow(input);
    } else if (strcmp(type, "format") == 0) {
        vuln_format_string(input);
    } else if (strcmp(type, "heap") == 0) {
        vuln_heap_overflow(input);
    }

    return 0;
}
