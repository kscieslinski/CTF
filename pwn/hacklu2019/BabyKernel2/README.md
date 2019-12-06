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

As this is my first kernel challenge, I will briefly describe what are all of those files for (note: as this is my first challenge I might be completely wrong).

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


Then we have `initramfs.cpio.gz`. It contains packed filesystem. We will find there often `flag` file and source or at least executables of vulnerable `modules`.

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

Now we are left with `run.sh` script:

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

I bet this is a lot (it was for me), and so for now you should only be looking for keywords such as: smep, smap, kaslr. This are the protections and so our attack technique will depend on whether they are enabled or disabled.
Here we have smep and smap enabled and no kaslr. I will explain them later on when we get to exploit phrase.


## References
