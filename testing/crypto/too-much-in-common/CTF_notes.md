# CTF Notes: Phi Too Much In Common

## Approach
1.  **Exploration**: Connected to `localhost:5000` and observed the menu.
2.  **Analysis**:
    *   The service provides `N`, `e`, `c` upon request.
    *   Collected multiple samples of `(N, e, c)` by connecting repeatedly.
    *   Discovered that the service reuses the **same Modulus N** with different Exponents `e` across different requests (Common Modulus Attack vulnerability).
3.  **Exploit Part 1 (Common Modulus)**:
    *   Found two samples with the same `N` and `gcd(e1, e2) = 1`.
    *   Used the extended Euclidean algorithm to find `a, b` such that `a*e1 + b*e2 = 1`.
    *   computed `m = c1^a * c2^b (mod N)`.
    *   Decrypted the message/password: `d0nt_reUs3_c0mm0n_m0duLus_iN_RSA`.
4.  **Exploit Part 2 (Recover Phi)**:
    *   Submitted the password to the service.
    *   Service provided `N`, `e`, `d` and asked for `phi(N)`.
    *   Used the relation `ed - 1 = k * phi(N)`.
    *   Approximated `k` and searched for integer `phi` that satisfies quadratic constraints (or just `phi = (ed-1)/k`).
    *   Found correct `phi`.
5.  **Flag Capture**:
    *   Submitted `phi` to the service.
    *   Received the flag.

## Findings & Observations
- The challenge name "Too Much In Common" hinted at the Common Modulus Attack.
- The "Phi" part hinted at the second stage where we calculate `phi`.
- Flag: `flag{aR3nT_U_tH3_RSA_ninJA}`

## Assumptions & Hypotheses
- The flag format provided in the instructions (`csawctf{...}`) might be a placeholder or the challenge uses `flag{...}`. I will report the exact string received.

## Decisions
- Completed the challenge.