# CTF Notes - ezROP

## Initial Setup
- Challenge Name: ezROP
- Category: pwn
- Connection: localhost:9999
- Description: Simple buffer overflow challenge, but reversed.

## Approach
- Initial analysis of provided files.
- Analyzed `main.c`:
    - `vul` function constructs a fake ROP chain in a local `rop` array.
    - It performs an out-of-bounds write: `rop[0x104] = rop`.
    - `rop` is a local `size_t` array of size 0x100 (256 entries, 2048 bytes).
    - `rop[0x104]` writes to index 260, which is `260 * 8 = 2080` bytes from start of `rop`.
- Analyzed `checksec`:
    - NX Enabled (Stack non-executable).
    - No PIE.
    - No Canary.

## Exploitation
1.  **Vulnerability**: The `vul` function pivots the stack to its local `rop` array, which executes a ROP chain that includes `readn` (vulnerable to BOF) and `check`.
2.  **Stack Pivot**: `vul` ends with `leave; ret`. The OOB write `rop[0x104] = rop` (which is effectively writing to saved RBP) ensures `rsp` pivots to `rop` array.
3.  **ROP Execution**: The pre-constructed ROP calls `readn` then `check` then returns to `main+34`.
4.  **Buffer Overflow**: `readn` reads into `main`'s `buf`. Since `check` returns to `main`'s epilogue (`leave; ret`), and `rbp` was popped from the stack (controlled by payload), we can pivot the stack again to our payload in `buf`.
5.  **Leak**:
    - Payload 1: `\x00` + Padding + Fake RBP + ROP Chain 1.
    - ROP Chain 1: `pop rdi; got_puts; puts; main`.
    - Leaked `puts` address: `0x...420`.
    - Identified Libc: `libc6_2.31-0ubuntu9.9_amd64` (Ubuntu 20.04).
6.  **Shell**:
    - Payload 2: `\x00` + Padding + Fake RBP + ROP Chain 2.
    - ROP Chain 2: `ret; pop rdi; bin_sh; system`.
    - Executed `cat flag`.

## Flag
`flag{53bb4218b851affb894fad151652dc333a024990454a0ee32921509a33ebbeb4}`
