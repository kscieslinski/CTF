# solid_core (kernel, +smep, +smap, +kaslr, modprobe_path)

## Enumeration
I've started with checking the content of `solid_core.cpio` to retrieve module binary:

```console
$ ls
bzImage  run.sh  solid_core.cpio
$ mkdir extracted
$ cd extracted
$ cat ../solid_core.cpio | cpio -idvm
simp1e.ko
init
[...]
23550 blocks
```

To make reverse engineering easier I've also disabled dmesg restrictions and increased our privilages to root:

```bash
$ cat init
[...]
# echo 1 > /proc/sys/kernel/kptr_restrict
# echo 1 > /proc/sys/kernel/dmesg_restrict
[...]
#setsid /bin/cttyhack setuidgid 1000 /bin/sh
/bin/sh
[...]

$ find . -print0 | cpio --null -ov --format=newc >../solid_core.cpio
[...]
```

The RE part was the hardest one for me. You can find simplified (I havn't included mutexes and I've skiped many basic error checks) pseudocode can be found [here](csaw.c)

The basic idea is that a user can create channels:

```c
typedef struct channel_t
{
    int ref_count;
    unsigned int index;
    char *buf;
    size_t buf_size;
    size_t pos;
} channel_t;
```

with any buf_size. Moreover she/he can increase and decrease buf size, read and write to it.