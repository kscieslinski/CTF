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
size_t nslots = 0;


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

