# The Big Bang - Challenge Write-up

## 1. Reconnaissance & Initial Analysis
We were provided with a Python script `challenge.py` and a `challenge.json` file.
The `challenge.py` script implements a custom crypto/logic challenge.
Key observations:
- **MAGIC Constant**: The script had `MAGIC = ?`. By inspecting the length of constant `K1`, I determined `MAGIC = 73`. The number 73 is referenced in "The Big Bang Theory" as the "best number".
- **Constants**: `K1` through `K6` are byte strings of length 73.
- **Logic Function**: A function `foo(x, y, z, w)` implements a complex bitwise logic function.
- **Goal**: The server generates random keys and an IV. It asks for input. If the input, processed through the logic function, matches the running XOR sum of the hidden keys, we get the flag.

## 2. Vulnerability Identification
The core check is inside the `main` loop:
```python
output = foo(output, foo(keys[i], foo(inp[i], iv_b[i], K5, K6), K3, K4), K1, K2)
if not guardian(output, i, keys): ...
```
`guardian` checks if `output` equals the cumulative XOR of `keys` up to step `i`.
Let $T_i$ be the XOR sum of keys $k_0 \dots k_i$.
We require:
$T_i = \text{foo}(T_{i-1}, \text{foo}(k_i, \text{foo}(\text{inp}_i, \text{IV}_i, K5, K6), K3, K4), K1, K2)$
Since $T_i = T_{i-1} \oplus k_i$, this simplifies to:
$T_{i-1} \oplus k_i = \text{foo}(T_{i-1}, \dots, K1, K2)$

The critical vulnerability is that this equation must hold for **unknown, random** keys $k_i$.
This implies that for each bit position, there exists an input bit $x$ (from `inp[i]`) such that the equation holds **regardless of the value of the key bit $k$**.
Essentially, the logic gate structure is "reversible" or has a "universal solution" for $x$ given the other constants.

## 3. Exploitation Strategy
1.  **Bitwise Independence**: The operations (`&`, `|`, `^`, `~`) are bitwise. We can solve for each bit of each byte of the input independently.
2.  **Solver Construction**:
    We need to find input bit $x$ such that for a given IV bit $v$, previous output bit $p$, and constants $k1..k6$, the following holds for both $k=0$ and $k=1$:
    $p \oplus k = \text{Logic}(p, \text{Logic}(k, \text{Logic}(x, v, k5, k6), k3, k4), k1, k2)$
    
    My solver iterates $x \in \{0, 1\}$ and checks if the condition holds for all $p, k \in \{0, 1\}$.
    
3.  **Correct Constants**: A critical step was ensuring the `K` constants were exactly as in the challenge file. I achieved this by reading the original `challenge.py` and patching it programmatically rather than copy-pasting, which avoided encoding errors (specifically a missing byte in `K1` due to `\x0b`).

## 4. Exploit Development
I created a script `exploit_final.py` which:
1.  Connects to the challenge server.
2.  Retrieves the random IV string.
3.  For each block (73 total) and each byte (73 total) and each bit (8 total):
    - Extracts the corresponding bits of `K1..K6`.
    - Extracts the IV bit for the block.
    - Uses the bitwise solver to find the correct input bit $x$.
    - Reconstructs the input bytes.
4.  Sends the constructed payload.
5.  Receives the flag.

## 5. Final Exploit
The exploit script reads the challenge source code to extract constants safely, patches the `MAGIC` value, and appends the solver logic.

**Captured Flag**:
`flag{5h3ld0n_54y5_7h47_7h3_b357_numb3r_1n_7h3_w0rld_15_73,_h3_15_r16h7!!}`
