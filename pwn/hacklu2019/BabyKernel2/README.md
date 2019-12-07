# Baby Kernel 2 (kernel, +smep, +smap, -kaslr)

## Enumeration
### Understanding what we are given
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

How can you communicate with module from code? Well, they usually come with char devices. They are placed in /dev folder.

## 
In this challenge we found 3 files inside initramfs.cpio.gz:
- lib/modules/4.19.77/kernel_baby_2.ko: kernel module binary. This file perhaps contains the vulnerability and in the end we will have to exploit it. It runs inside kernel so when exploited we can gain privilages escalation :)
- /dev/flux_baby_2: a char device used to communicate with the module. Standard functions to communicate with it are: `open`, `close`, `read`, `write`, `llseek`, `ioctl`.
- client_kernel_baby_2: in this specific challenge we cannot communicate with a char device as a user (chown 0:0 /dev in init file). But we can run ./client_kernel_baby_2 program which just wraps the `open`, `close`, ..., `ioctl` functions and invokes them on `/dev/flux_baby_2`. This means that our exploit will just communicate with this binary.


## References
- https://www.tldp.org/LDP/lkmpg/2.6/html/x181.html
- https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part1.html
- http://eternal.red/2019/sloppy-dev-writeup/