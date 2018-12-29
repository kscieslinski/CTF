import socketserver
import secrets

import Crypto.Util.Padding

from secureproc import SecureProc

with open('flag_easy.txt', 'rb') as f:
    FLAG_EASY = f.read()

with open('flag_hard.txt', 'rb') as f:
    FLAG_HARD = f.read()

class DemoTCPHandler(socketserver.StreamRequestHandler):

    def handle(self):
        self.wfile.write(b"The hard way or the easy way?\n")
        l = self.rfile.readline()
        if l.startswith(b'hard'):
            self.wfile.write(b"Good choice.\n")
            hard = True
            flag = FLAG_HARD
        elif l.startswith(b'easy'):
            self.wfile.write(b"Wuss.\n")
            hard = False
            flag = FLAG_EASY
        else:
            self.wfile.write(b"Um what? ... Eh, whatever.\n")
            hard = True
            flag = FLAG_EASY

        self.wfile.write(b"Look at what our secure processor can do!\n")
        proc = SecureProc()
        self.wfile.write(b"Making a key...\n")
        key = secrets.token_bytes(16)
        self.wfile.write(b"Writing the key to secure hardware...\n")
        for i, b in enumerate(key):
            proc.write_byte(i, b) # pozycja i odpowiadający jej bajt: 0 22, 1 61, .., 15 243 
        self.wfile.write(b"Forgetting the key...\n")
        del key
        self.wfile.write(b"Encrypting the flag with CBC...\n")
        iv = secrets.token_bytes(16)
        flag_padded = Crypto.Util.Padding.pad(flag, 16)
        enc_data = block = iv
        for i in range(0, len(flag_padded), 16): # dla kazdego bloku
            for j in range(16):
                proc.write_byte(0x10 + j, block[j] ^ flag_padded[i + j])
            block = bytearray(16)
            for j in range(16):
                block[j] = proc.read_byte(0x10 + j)
            enc_data += block
        self.wfile.write(f"The encrypted flag is {enc_data.hex()}.\n".encode())
        self.wfile.write(b"Send \"w <addr> <data>\" to write a byte to the secure processor.\n")
        self.wfile.write(b"Send \"r <addr>\" to read a byte from the secure processor.\n")
        print("-------ENDED INITIALIZATION PHRASE--------------")
        n = 0
        for l in self.rfile:
            try:
                l = l.decode().strip()
            except ValueError:
                self.wfile.write(b"Please speak UTF-8 to me.\n")
                continue
            if not l:
                continue
            l = l.split()
            if l[0] == 'w':
                if len(l) != 3:
                    self.wfile.write(b"Um?\n")
                    continue
                try:
                    addr = int(l[1], 16)
                    data = int(l[2], 16)
                    print(addr, data)
                except ValueError:
                    self.wfile.write(b"Um?\n")
                    continue
                if addr & ~0xff or data & ~0xff:
                    self.wfile.write(b"Um?\n")
                    continue
                proc.write_byte(addr, data)
            elif l[0] == 'r':
                if len(l) != 2:
                    self.wfile.write(b"Um?\n")
                    continue
                try:
                    addr = int(l[1], 16)
                except ValueError:
                    self.wfile.write(b"Um?\n")
                    continue
                if addr & ~0xff: # jesli addr >= 256, lub addr < 0
                    self.wfile.write(b"Um?\n")
                    continue
                data = proc.read_byte(addr)
                self.wfile.write(f"{data:02x}\n".encode())
            else:
                self.wfile.write(b"Um?\n")
                continue
            n += 1
            if hard and n > 1000:
                self.wfile.write(b"Request limit reached.\n")
                return


class DemoTCPServer(socketserver.ForkingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 31337

    with DemoTCPServer((HOST, PORT), DemoTCPHandler) as server:
        server.serve_forever()
