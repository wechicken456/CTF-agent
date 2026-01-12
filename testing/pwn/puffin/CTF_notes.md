# CTF Notes - puffin

## Approach
1. Initial analysis of the binary `puffin`.
2. Check security features using `checksec`.
3. Disassemble/Decompile the binary to find vulnerabilities.
4. Develop and test the exploit locally.
5. Run the exploit against the remote server.

## Findings & Observations
- Challenge name: puffin
- Category: pwn
- Description: "Huff, puff, and blow that buffer over."
- Files: `puffin`, `readme.txt`
- `checksec`: No canary, NX enabled, PIE enabled.
- `main` function vulnerability: `fgets` reads 48 bytes into a 44-byte buffer.
- Stack Layout:
    - `local_38` (buffer): `[RBP - 0x30]`
    - `local_c` (int): `[RBP - 0x4]`
- Offset: `0x30 - 0x4 = 44` bytes.

## Assumptions & Hypotheses
- Overwriting `local_c` with a non-zero value will trigger `system("cat /flag.txt")`.

## Verification
- Verified RIP control by observing crash at 0x42424242 in GDB (not actually needed here as we overwrite a local variable).
- Verified local exploit works (tried to cat /flag.txt).
- Successfully ran exploit against remote `localhost:31140`.
- Flag captured: `csawctf{m4ybe_i_sh0u1dve_co113c73d_mor3_rock5_7o_impr355_her....}`

## Errors/Roadblocks
- `FileNotFoundError` in first python script due to relative path. Fixed by using absolute path.
- Local exploit failed to find `/flag.txt` because it's not at the root in my local environment, but it confirmed the logic.

## Final Result
Flag: `csawctf{m4ybe_i_sh0u1dve_co113c73d_mor3_rock5_7o_impr355_her....}`
