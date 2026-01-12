import os

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

known_plain = b"Slowking-Poison-Psychic"
known_cipher = b'{w\xca\xba\xc7_u\xc9\x8a\x89\xfd\x95\xbes\xadj\xfe\xdcv\xf6\xe4\xd2\xaa'

key = xor(known_plain, known_cipher)
print(f"Recovered Key ({len(key)} bytes)")

file_path = '/home/pwnphofun/Code/programming/MCP/ctf-agent/testing/pwn/crypto/gotta-crack-them-all/encrypted_passwords.txt'
if os.path.exists(file_path):
    with open(file_path, 'rb') as f:
        content = f.read()
    
    lines = content.split(b'\n')
    for i, line in enumerate(lines):
        if not line: continue
        decrypted = xor(line, key)
        print(f"{i}: Len={len(line)} Decrypted={decrypted}")
else:
    print("File not found.")

