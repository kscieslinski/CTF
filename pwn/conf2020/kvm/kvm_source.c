#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <linux/kvm.h>


/* CR0 bits */
#define CR0_PE 1u
#define CR0_MP (1U << 1)
#define CR0_EM (1U << 2)
#define CR0_TS (1U << 3)
#define CR0_ET (1U << 4)
#define CR0_NE (1U << 5)
#define CR0_WP (1U << 16)
#define CR0_AM (1U << 18)
#define CR0_NW (1U << 29)
#define CR0_CD (1U << 30)
#define CR0_PG (1U << 31)

#define CR4_PAE (1U << 5)

#define EFER_LME (1U << 8) // Long mode enable
#define EFER_LMA (1U << 10) // long mode active




void read_n(int count, void *dst)
{
    int to_read = count;
    char *dst_ptr = dst;
    while (to_read > 0) {
        int read_res = read(0, dst_ptr, to_read);
        to_read -= read_res;
        dst_ptr += read_res;
    }
}


int main()
{
    char guest_mem[0x8000];

    memset(&guest_mem, 0, 0x8000);
    char *aligned_guest_mem = guest_mem + (4096 - guest_mem % 4096);

    uint code_size = -1;
    read_n(sizeof(uint), code_size);
    if (code_size > 0x4000) {
        puts("\n[init] hold your horses");
        return 1;
    }

    read_n(code_size, aligned_guest_mem);
    
    int kvm_fd = open("/dev/kvm", O_CLOEXEC|O_RDWR);

    uint vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);


    struct kvm_userspace_memory_region region = {
        .slot = 0,
        .flags = 0,
        .guest_phys_addr = 0,
        .memory_size = 0x8000,
        .userspace_addr = aligned_guest_mem
    };
    ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &region);
    
    
    int vcpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0);

    int vcpu_mmap_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    char *run_mem = mmap(NULL, vcpu_mmap_size, PROT_READ|PROT_WRITE, MAP_SHARED, vcpu_fd, 0);

    struct kvm_regs guest_regs;
    memset(&guest_regs, 0, sizeof(guest_regs));
    guest_regs.rsp = 0xff0;
    guest_regs.rflags = 2; // required
    ioctl(vcpu_fd, KVM_SET_REGS, &guest_regs);

    struct kvm_sregs guest_sregs;
    ioctl(vcpu_fd, KVM_GET_SREGS, &guest_sregs);

    // Setup paging long mode.
    guest_sregs.cr0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
    guest_sregs.cr4 = CR4_PAE;
    guest_sregs.efer = EFER_LMA | EFER_LME;
    guest_sregs.cr3 = 0x4000;
    (__u64*)(aligned_guest_mem + 0x4000) = 0x5003; // P4 Table[0]
    (__u64*)(aligned_guest_mem + 0x5000) = 0x6003; // P3 Table[0]
    (__u64*)(aligned_guest_mem + 0x6000) = 0x7003; // P2 Table[0]
    (__u64*)(aligned_guest_mem + 0x7000) = 0x3;    // P1 Table[0]
    (__u64*)(aligned_guest_mem + 0x7008) = 0x1003; // P1 Table[1]
    (__u64*)(aligned_guest_mem + 0x7010) = 0x2003; // P1 Table[2]
    (__u64*)(aligned_guest_mem + 0x7018) = 0x3003; // P1 Table[3]
    // meaning 0x0, 0x1000, 0x2000, 0x3000 are physical pages


    // Setup segments
    struct kvm_segment seg = {
        .base = 0,
        .limit = 0xffffffff,
        .selector = 1 << 3,
        .present = 1,
        .type = 11, /* Code: execute, read, accessed */
        .dpl = 0,
        .db = 0,
        .s = 1, /* Code/data */
        .l = 1,
        .g = 1, /* 4KB granularity */
    };
    sregs->cs = seg;
    
	seg.type = 3; /* Data: read/write, accessed */
	seg.selector = 2 << 3;
	sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;

    ioctl(vcpu_fd, KVM_SET_SREGS, &guest_sregs);

    
    while (true) {
        ioctl(vcpu_fd, KVM_RUN, 0);
        exit_reason = run_mem->exit_reason;
        if (exit_reason == KVM_EXIT_HLT || exit_reason == KVM_EXIT_SHUTDOWN)
            break;
        if (exit_reason == KVM_EXIT_IO) {
            if (run_mem->io.direction == KVM_EXIT_IO_OUT && run_mem->io.port == 0x3f8) {
                printf("%.*s", 
                    run_mem->io.count * run_mem->io.size,
                    run_mem->request_interrupt_window + run_mem->io.data_offset);
            }
        }
        printf("\n[loop] exit reason: %d\n", exit_reason);
    }
    puts("\n[loop] goodbye!");

    return 0;
}