# CTF Notes - target_practice

## Approach
1. Initial reconnaissance of the binary.
2. Static analysis with Ghidra/Decompiler.
3. Dynamic analysis with GDB.
4. Exploit development.

## Findings & Observations
- Challenge Name: target_practice
- Category: pwn
- URL: localhost:31138
- Binary: `target_practice`
- Binary Protections:
  - Arch: amd64-64-little
  - RELRO: Partial RELRO
  - Stack: Canary found
  - NX: NX enabled
  - PIE: No PIE (0x400000)
  - Stripped: No
- Vulnerability: The `main` function reads a hex value into a function pointer and then calls it.
- Target: `cat_flag` function at `0x400717`.

## Assumptions & Hypotheses
- Providing the address of `cat_flag` (0x400717) to the program will cause it to execute `system("cat /flag.txt")`.

## Decisions
- Use `127.0.0.1:31138` to connect to the challenge server.
- Send `400717` to the server.

## Verification
- Successfully verified RIP control by jumping to `cat_flag`.
- Captured flag: `csawctf{y0ure_a_m4s7er4im3r}`
