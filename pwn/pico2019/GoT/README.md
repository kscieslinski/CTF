# GoT 350 points (pwn, pico, global-offset-table)

Notes:
- source code given
- binary given

### Enumeration
The program is very simple. It allows us to override exactly one address in the memory and to get the flag we have to call `win` function.

It also gives us a great hint. The GoT stands for global-offset-table. What is it? When a program is statically linked it will be self sufficient and so it will contain all code it uses inside the binary. This comes with huge overhead and most programs are nowdays dynamicaly linked and so they can share libraries.

To see the overhead let's compile this simple program

```c
// test.c
#include <stdio.h>

int main() {
    puts("Hello world");
    return 0;
}
```

First as statically linked binary:

```bash
$ gcc test.c -o test-statically-linked -static
```

And then as dynamically linked one (no flag needed as it is default)

```bash
$ gcc test.c -o test-dynamically-linked
```

Let's compare the sizes:

```bash
$ size test-staticlly-linked
text	   data	    bss	    dec	    hex	filename
743281	  20876	   5984	 770141	  bc05d	test-statically-linked
$ size test-dynamically-linked
text	   data	    bss	    dec	    hex	filename
1514	    600	      8	   2122	    84a	test-dynamically-linked
```

Bum, 743281B vs 1514B!

Ok, so where the GoT comes into play? Well when compiling a dynamicaly-linked binary we don't know the address of library functions. Let's consider the above example.
When we dissassemble it, we can see that the call to `puts` leads to @plt (procedure linkage table) table instead of a raw address.

```bash
000000000000063a <main>:
 63a:	55                   	push   rbp
 63b:	48 89 e5             	mov    rbp,rsp
 63e:	48 8d 3d 9f 00 00 00 	lea    rdi,[rip+0x9f]
 645:	e8 c6 fe ff ff       	call   510 <puts@plt>
 64a:	b8 00 00 00 00       	mov    eax,0x0
 64f:	5d                   	pop    rbp
 650:	c3                   	ret    
 651:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
 658:	00 00 00 
 65b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
```

Seems complicated? Believe me it's not. We will modify our simple example to show how @plt and @got works.

```c
// test.c
#include <stdio.h>

int main() {
    puts("First puts call");
    puts("Second puts call");
    return 0;
}
```

Let's examine the flow under gdb.

```bash
$ gdb -q test
Reading symbols from test...(no debugging symbols found)...done.
gdb-peda$ start
```

Continue till first `puts`:
```gdb
gdb-peda$ pd
[...]
=> 0x0000555555554645 <+11>:	call   0x555555554510 <puts@plt>
[...]
gdb-peda$ si
=> 0x555555554645 <puts@plt>:	jmp    QWORD PTR [rip+0x200aba]        # 0x555555754fd0
 | 0x555555554516 <puts@plt+6>:	push   0x0
 | 0x55555555451b <puts@plt+11>:	jmp    0x555555554500
gdb-peda$ x/1gx 0x555555754fd0
0x555555554516
```

First `puts@plt` instruction is a jmp to the address placed at `puts@got` (0x555555754fd0) table. At 0x555555754fd0 we can find the address of second `puts@plt` instruction. Werid? Not at all! The second and third `puts@plt` instruction is responsible for calling a dynamic linker which will find a `puts@libc` address and place it in `puts@got` table. So the second time we will directly jmp to `puts@libc` instead of invoking the linker.

Let's break at second puts.

```gdb
gdb-peda$ b *0x0000555555554651 # address of second puts
Temporary breakpoint 1, 0x000055555555463e in main ()
gdb-peda$ c
Continuing.
First puts call
Breakpoint 2, 0x0000555555554651 in main ()
gdb-peda$ x/1gx 0x555555754fd0
0x555555754fd0:	0x00007ffff7a649c0
gdb-peda$ x/3i 0x00007ffff7a649c0
   0x7ffff7a649c0 <_IO_puts>:	push   r13
   0x7ffff7a649c2 <_IO_puts+2>:	push   r12
   0x7ffff7a649c4 <_IO_puts+4>:	mov    r12,rdi
```

This time under `puts@got` we found address to `puts@libc` just as expected!

### Exploit
After above explanation it should be obvious what we need to override. We will override the address of `exit@got` with address of `win` function. So when program will try to call `exit(0)` it will instead jmp to `win` function. 