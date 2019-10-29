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

## Back to leaking libc
Ok, so having setup the environment we can now try to leak the libc_base address. Let's open the binary and proceed to call to read so we can determinate address of name_buf (should be second argument).

and investigate the initial values stored in our name_buf.


```gdb
$ LD_PRELOAD=$PWD/libc_32.so.6 gdb ./dubblesort
gef➤ start
gef➤ ni # till we reach read
gef➤ context
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffceb0│+0x0000: 0x00000000	 ← $esp
0xffffceb4│+0x0004: 0xffffceec  →  0x000030d7
----------------------------------------
   0x56555a11 <main+78>        mov    DWORD PTR [esp], 0x0
 → 0x56555a18 <main+85>        call   0x56555630 <read@plt>
   ↳  0x56555630 <read@plt+0>     jmp    DWORD PTR [ebx+0xc]
      0x56555636 <read@plt+6>     push   0x0
      0x5655563b <read@plt+11>    jmp    0x56555620