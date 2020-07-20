# vm_no_fun (custom vm)

In this challenge we are provided with a custom virtual machine which emulates operations on CPU and IO. In fact there are three virtual machines, but they all work in very similar way.
I recommend you watch [How to build a Virtual Machine](https://www.youtube.com/watch?v=OjaAToVkoTw) if you want to get more familiar with vms.

Also please note that even thought I've tried to reverse engineer the whole program I gave up after reverse engineering half of first virtual machine and just used source code which I've found [here](https://github.com/SECCON/SECCON2017_online_CTF/tree/master/pwn/500_vm_no_fun/build). If the link is down you can still find it in `source-code/` folder.

## Internals
As stated above we are given three very simple virtual machines. Each of them consists of 14 registers and buffer of size 0xffff bytes. This buffer represents virtual machine memory space and is divided into segments. Segmentation looks the same for each vm:

```
code_segment:    [0x0   , 0x3fff]
data_segment:    [0x4000, 0x6fff]
extra_segment_r: [0x7000, 0x7fff]
extra_segment_w: [0x8000, 0x8fff]
stack_segment:   [0x9000, 0xffff]
```

This segmentation is achieved with special purpose registers: `cs`, `ds`, `es`, `ss`. So let's say we have an operation which will pop value from the stack:

```
OPCODE_POP_WORD:
    if (ss * 16 + sp > MEM_SIZE)
        raise(SIGSEGV);

    if (dest_word)
        *dest_word = *((uint16_t *) &vm1_mem[ss * 16 + sp]);
```

![](img/segments.png)

Code segment, data segment and stack all speak for itself. The interesting is extra segment. It is again divided into two parts each 0x1000 bytes and is used for interacting with the other vms or IO in case of VM1.
The point is that we can interact using stdin/stdout only with VM1. When we run vm2 it will load code from vm1 extra_segment_write instead of stdin.

![](img/interaction.png)


## Vulnerabilities