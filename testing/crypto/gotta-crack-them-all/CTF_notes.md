# CTF Notes - gotta-crack-them-all

## Initial Reconnaissance
- Files provided: `challenge.json`, `encrypt.py`, `encrypted_passwords.txt`, `leaked_password.txt`.
- Goal: Decrypt the passwords to find the flag.
- Category: Crypto (Many-Time Pad / Stream Cipher key reuse).

## Findings
- `encrypt.py` shows a simple XOR cipher using a static key from `key.txt`.
- `encrypted_passwords.txt` contains multiple ciphertexts.
- `leaked_password.txt` contains `Cacturne-Grass-Dark`.
- There is a service on port 5000 that encrypts passwords.

## Strategy
1. The service allows encrypting arbitrary text.
2. If we send a plaintext of all Null bytes (`\x00`), the ciphertext will be `\x00 ^ Key = Key`.
3. Alternatively, sending any known plaintext `P` allows recovering `K = C ^ P`.
4. Once `K` is recovered, decrypt all lines in `encrypted_passwords.txt`.
5. The flag is the admin's password wrapped in `flag{...}`.

## Execution
1. Tried sending random text to service, failed ("pre-approved" only).
2. Sent `Cacturne-Grass-Dark` (from `leaked_password.txt`).
3. Received ciphertext.
4. Recovered 19 bytes of key.
5. Decrypted `encrypted_passwords.txt`.
6. Observed partially decrypted passwords, specifically `Slowking-Poison-Psy`.
7. Guessed `Slowking-Poison-Psychic`.
8. Sent `Slowking-Poison-Psychic` to service.
9. Recovered 23 bytes of key.
10. Decrypted `encrypted_passwords.txt` again.
11. Found line 49: `1n53cu2357234mc1ph32` (20 bytes).
12. Verified `Kingler-Water` decrypted correctly, confirming key.

## Result
- Admin password: `1n53cu2357234mc1ph32`.
- Flag: `flag{1n53cu2357234mc1ph32}`.
