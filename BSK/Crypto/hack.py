import socket
from Crypto.Cipher import AES

BLOCK_SIZE = 16

def readline(s):
    line = b''
    while True:
        b = s.recv(1)
        if len(b) == 0:
            continue
        line += b
        if b == b'\n':
            break
    line = line.decode('utf-8').strip()
    #print("Server: " + line)
    return line

def init_conversation(s):
    l = readline(s)
    assert l == 'The hard way or the easy way?'
    s.send(b'easy\n')

    l = readline(s)
    assert l == 'Wuss.'
    l = readline(s)
    assert l == 'Look at what our secure processor can do!'
    l = readline(s)
    assert l == 'Making a key...'
    l = readline(s)
    assert l == 'Writing the key to secure hardware...'
    l = readline(s)
    assert l == 'Forgetting the key...'
    l = readline(s)
    assert l == 'Encrypting the flag with CBC...'

    l = readline(s)
    assert 'The encrypted flag is' in l
    ctx = l[len('The encrypted flag is '):-1]
    iv = ctx[:BLOCK_SIZE * 2]
    enc_flag = ctx[BLOCK_SIZE * 2:]

    l = readline(s)
    assert l == 'Send "w <addr> <data>" to write a byte to the secure processor.'
    l = readline(s)
    assert l == 'Send "r <addr>" to read a byte from the secure processor.'

    return bytes.fromhex(iv), bytes.fromhex(enc_flag)

def set_key_bit(s, k, pos):
    s.send(b'w ' + bytes(hex(pos), 'utf-8') + b' ' + bytes(hex(k), 'utf-8') + b'\n')

def set_key(s, key):
    for i in range(BLOCK_SIZE):
        set_key_bit(s, key[i], i)

def set_data_bit(s, c, pos):
    pos += BLOCK_SIZE
    s.send(b'w ' + bytes(hex(pos), 'utf-8') + b' ' + bytes(hex(c), 'utf-8') + b'\n')

def set_data(s, data):
    for i in range(BLOCK_SIZE):
        set_data_bit(s, data[i], i)

def read_ctx_byte(s, pos):
    pos += BLOCK_SIZE
    s.send(b'r ' + bytes(hex(pos), 'utf-8') + b'\n')
    l = readline(s)
    assert len(l) == 2
    return bytes.fromhex(l)

def read_ctx(s):
    ctx = b''
    for i in range(BLOCK_SIZE):
        ctx += read_ctx_byte(s, i)
    return ctx

def recover_key_bit(s, pos):
    plx = b'drzewwaa atakoow'
    set_data(s, plx) 
    ctx = read_ctx(s)
    for i in range(256):
        set_key_bit(s, i, pos)
        set_data(s, plx)
        ctx2 = read_ctx(s)
        if ctx == ctx2:
            return bytes([i])
    assert False

def bxor(b1, b2):
    result = bytearray()
    for b1, b2 in zip(b1, b2):
        result.append(b1 ^ b2)
    return bytes(result)

def main():
    s = socket.socket()
    s.connect(('h4x.0x04.net', 31337))

    iv, enc_flag = init_conversation(s)
    print(b"*********** GIVEN ************")
    print(b"iv: " + iv)
    print(b"enc_flag: " + enc_flag)

    print(b"****** HACKING PHRASE ********")
    key = b''
    for i in range(BLOCK_SIZE):
        key += recover_key_bit(s, i)
        print(key)
    print(b"Found key: " + key)

    print(b"********* RESULT *************")
    aes = AES.new(key, AES.MODE_ECB)
    otp = iv
    dec_flag = b''
    for i in range(0, len(enc_flag), BLOCK_SIZE):
        ctx_block = enc_flag[i:i + BLOCK_SIZE]
        dec_block = aes.decrypt(ctx_block)
        dec_flag += bxor(dec_block, otp)
        otp = ctx_block
    print(b"dec_flag: " + dec_flag)

    s.close()


if __name__ == '__main__':
    main()