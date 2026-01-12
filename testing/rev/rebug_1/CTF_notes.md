# CTF Notes: Rebug 1

## 1. Reconnaissance & Initial Analysis

### Initial File Identification
- Binary: `test.out`
- Architecture: `amd64-64-little`
- Security:
    - RELRO: Partial
    - Canary: No
    - NX: Yes
    - PIE: Yes
    - Stripped: No (Symbols present)

### Tooling Confusion
Initial static analysis via `ghidra` tools provided decompilation that did NOT match the runtime behavior observed in GDB.
- `ghidra` reported `main` calling `vul` and a complex ROP chain construction.
- `gdb` (runtime) showed `main` calling `scanf`, `EVP_DigestUpdate`, etc.
- `readelf -s` confirmed `main` is at offset `0x11c9`, matching GDB.
- The discrepancy suggests the `ghidra` tool output might have been stale or incorrect for this specific binary instance.

## 2. Vulnerability Identification & Logic Analysis

### Runtime Logic (Corrected)
Using GDB and `xxd`, the actual logic of `main` (offset `0x11c9`) was determined:
1.  **Prompt:** Prints "Enter the String: ".
2.  **Input:** Calls `scanf("%s", buffer)` where buffer is at `rbp-0x400`.
    -   *Vulnerability:* `scanf` with `%s` allows buffer overflow, but is not needed for the intended solution.
3.  **Length Check:** Loops through the input string.
    -   Counts characters until `\0`.
    -   Compares length to `0xc` (12).
4.  **Success Condition:**
    -   If length == 12:
        -   Prints "that's correct!".
        -   Calculates MD5 hash of the string "12" (hardcoded at `0x202a`).
        -   Prints `csawctf{%02x%02x...}` using the MD5 hash bytes.
    -   If length != 12:
        -   Prints "that isn't correct, im sorry!" and exits.

### The "Bug"
The challenge description "Rebug 1" implies we need to fix or find a bug.
The "bug" here is that the flag generation depends ONLY on the length of the input being 12, not the content of the input (it hashes a constant string "12"). Or perhaps the "bug" refers to the misleading static analysis artifacts?

## 3. Exploitation

### Strategy
Provide any input string of length 12 to pass the check and trigger the flag printing.

### Execution
Command: `echo -n "AAAAAAAAAAAA" | ./test.out`

### Output
```
Enter the String: that's correct!
csawctf{c20ad4d76fe97759aa27a0c99bff6710}
```

## 4. Final Flag
`csawctf{c20ad4d76fe97759aa27a0c99bff6710}`
