#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <fcntl.h>


void set_rlimits()
{
    struct rlimit limit;

    limit.rlim_cur = 0x6400000;
    limit.rlim_max = 0x6400000;
    setrlimit(RLIMIT_AS, &limit);
    limit.rlim_cur = 10;
    limit.rlim_max = 10;
    setrlimit(RLIMIT_CPU, &limit);
    limit.rlim_cur = 1000;
    limit.rlim_max = 1000;
    setrlimit(RLIMIT_FSIZE, &limit);
    limit.rlim_cur = 100;
    limit.rlim_max = 100;
    setrlimit(RLIMIT_NOFILE, &limit);
    limit.rlim_cur = 0x28;
    limit.rlim_max = 0x28;
    setrlimit(__RLIMIT_NPROC, &limit);
}

int exec_shellcode()
{
    char *code, *code_ptr;

    syscall(__NR_alarm, 20);

    code = mmap(NULL, 10, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    printf("> ");
    code_ptr = code;
    do
    {
        if (read(0, code_ptr, 1) != 1)
        {
            exit(0);
        }
        code_ptr += 1;
    } while (code_ptr != code + 10);

    (*code)();
    return 0;
}

void check_syscall(pid_t child_pid, struct user_regs_struct *regs)
{
    char pathname_part0[8];
    char pathname_part1[8];

    if (regs.orig_rax == __NR_lseek || regs.orig_rax == __NR_read ||
        regs.orig_rax == __NR_write || regs.orig_rax == __NR_close ||
        regs.orig_rax == __NR_fstat || regs.orig_rax == __NR_exit ||
        regs.orig_rax == __NR_exit_group || regs.orig_rax == __NR_getpid)
        return 0;

    if (regs.orig_rax == __NR_alarm)
    {
        /* Allow only short alarms. */
        return regs.rdi > 20;
    }

    if (regs.orig_rax == __NR_munmap ||
        regs.orig_rax == __NR_mprotect ||
        regs.orig_rax == __NR_mmap)
    {
        return regs.rsi <= 0x1000;
    }

    if (regs.orig_rax == __NR_open)
    {
        /* Flags must be O_RDONLY. */
        if (regs.rsi != 0)
            return 1;

        pathname_part0 = ptrace(PTRACE_PEEKDATA, child_pid, regs.rdi, 0);
        pathname_part1 = ptrace(PTRACE_PEEKDATA, child_pid, regs.rdi + 8, 0);
        // TODO some extra checks. For example whether the path contains a "flag" string in it.
    }

    return 1;
}

int main()
{
    pid_t child_pid, parent_pid;
    int status, waitpid_res;
    struct user_regs_struct regs;
    char *str;

    set_rlimits();
    alarm(10);

    printf("o hai\n");

    if (access("./flag", 4) != 0)
    {
        perror("flag access fail\n");
        return 1;
    }

    child_pid = fork();
    switch (child_pid)
    {
    case 0:
        /* Child job. */
        prctl(PR_SET_PDEATHSIG, SIGKILL);

        parent_pid = getppid();
        if (parent_pid == 1)
        {
            printf("child is orphaned\n");
            exit(1);
        }

        if (ptrace(PTRACE_TRACEME, 0, 0, 0))
        {
            perror("child traceme");
            exit(1);
        }

        kill(getpid(), SIGSTOP);
        exec_shellcode();
        break;

    default:
        /* Parent job. */
        /* Wait for any child.  */
        waitpid_res = waitpid(child_pid, &status, __WALL);
        if (waitpid_res < 0 || WTERMSIG(status) || MAKRO2)
        {
            perror("initial waitpid fail");
        }

        alarm(30);
        ptrace(PTRACE_SETOPTIONS, child_pid, 0);

        while (ptrace(PTRACE_SYSCALL, child_pid, 0))
        {

            if (waitpid(child_pid, &status, __WALL) < 0)
            {
                err_msg = "waitpid fail";
                goto check_for_echild;
            }
            if (!WTERMSIG(status))
            {
                printf("so long, sucker");
                goto just_exit;
            }
            if (!MAKRO2(status))
            {
                printf("child signal\n");
                continue;
            }

            if (ptrace(PTRACE_GETREGS, child_pid, 0, regs))
            {
                perror("ptrace getregs");
                goto exit_kill_child;
            }

            if (!check_syscall(child_pid, regs))
            {
                printf("allowed syscall %lld(%lld, %lld, %lld, %lld)\n", regs.orig_rax,
                       regs.rdi, regs.rsi, regs.rdx, regs.r10);
            }
            else
            {
                printf("blocked syscall %lld\n", regs.orig_rax);
                regs.orig_rax = 1;
                regs.rdi = 1;
                regs.rdx = 17;
                regs.rsi = regs.rsp;
                if (ptrace(PTRACE_SETREGS, child_pid, 0, regs))
                {
                    perror("ptrace setregs");
                    goto exit_kill_child;
                }

                for (int i = 0; i < 3; i++)
                {
                    str = "get clapped sonn\n";
                    ptrace(PTRACE_POKEDATA, child_pid, regs.rsp + i * 8, (*(uint64_t *)str + i * 8));
                }
            }

            if (ptrace(PTRACE_SYSCALL, child_pid, 0, 0))
            {
                err_msg = "ptrace syscall 2";
                goto check_for_echild;
            }
            if (waitpid(child_pid, &status, __WALL) < 0)
            {
                err_msg = "waitpid fail";
                goto check_for_echild;
            }
            if (!WTERMSIG(status))
            {
                printf("so long, sucker");
                goto just_exit;
            }
        }

        break;
    }

check_for_echild:
    if (errno != ECHILD)
    {
        perror(err_msg);
        goto exit_kill_child;
    }
    goto just_exit;

exit_kill_child:
    kill(child_pid, SIGKIL);
    return 1;
just_exit:
    return 0;
}