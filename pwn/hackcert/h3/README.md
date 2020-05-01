# Heroes of Might and PWN (windows, seh, game, VirtualAlloc)
This was a great challenge! It has also the lowest number of solves at [hackcert](https://hack.cert.pl/challenges) platform! It took me some time as I'm new to windows hacking and I spend a lot of time looking for setting the lab.

## CVE
From the story in task description we know that the server is running patched demo version of Heroes and Might and Magic 3. The unpatched version was vulnerable to some kind of popular exploit as it has been exploited by a script kiddie.

Searching through exploitdb I have quickly found the ['Heroes of Might and Magic III .h3m Map file Buffer Overflow'](https://www.exploit-db.com/exploits/37737) exploit from task description.

The exploit description states:
```
This module embeds an exploit into an ucompressed map file (.h3m) for
Heroes of Might and Magic III. Once the map is started in-game, a
buffer overflow occuring when loading object sprite names leads to
shellcode execution.
```

This raw description doesn't tell us to many details about where the vulnerability occurs. It just says that there is a buffer overflow in part of program responsible for parsing the sprite names.

## Patch
But we also received the patched version of the game. Problem was that the two executables: `h3demo.exe` and `h3demo_unpached.exe` are huge and I didn't want to reverse them manualy.
I needed a way to compare two raw `.exe` files. I love Ghidra and I find it way more intuitive then IDA, but I have to say that there is one big advantage of IDA over Ghidra – the number of avaible plugins.

As you have perhaps guessed, I've found <b>amazing</b> plugin for comparing `exe` files. [diaphora](https://github.com/joxeankoret/diaphora) is not only well documented but really simple to use.

And so diaphora has found one function which is different between versions:

![](img/diaphora_diff.png)

it also allows us to compare the function in pseudocode, or display the differences on the graph.

## RE
Now I had to understand the patch. Moreover I also had to understand the orginal vulnerability as I didn't look into it yet. With some staring at the assembly and some testing on unpatched version I have successfuly reversed the critical part of the code.

While testing I had some problems with running Heroes 3 under x64dbg as the game window was covering the debugger. I've bypassed this by using `window key + tab` and dragging the game window to the other desktop. But if you know a better solution, please share:)

But back to the pseudocode. I've confirmed that unpatched version is vulnerable to simple buffer overflow. The program allocates 96 bytes for sprite name and then reads the sprite_name_len from map and finally reads the sprite_name_len bytes into sprite_name.

Unpatched:
```c
char sprite_name[96];
DWORD sprite_name_len;

read_n_bytes_from_map(raw_map, &sprite_name_len, sizeof DWORD);
read_n_bytes_from_map(raw_map, sprite_name, sprite_name_len);
```

What is interesting, the patched version doesn't mitigate the buffer overflow. But it checks if the provided sprite_name contains more then one null byte (normal strings have just one, the ending null byte). If it does, it crashes the application by moving 0 under address 0 and so causing SIGSEV.

```c
char sprite_name[96];
DWORD sprite_name_len, null_bytes_num;

read_n_bytes_from_map(raw_map, &sprite_name_len, sizeof DWORD);
read_n_bytes_from_map(raw_map, sprite_name, sprite_name_len);

/* Check if sprite name contains no more then one null byte. */
for (int i = sprite_name_len; i >= 0; i--) {
    if (sprite_name[i] == 0)
        null_bytes_num += 1;
}
if (null_bytes_num > 1) {
    /* Crash application. */
    __asm__("mov [0], 0;\n"::);    
}
```

## SEH
At first I thought of some kind of null byte free payload. But to succeed I would need to understand the rest of the flow of the vulnerable function. In the orginal exploit they mention a `Anticrash` gadgets. Both contain null bytes. This is because the `demo.exe` is not position independend and will always be loaded at default 0x00400000 address (so any gadget will have leading 00 byte).

But thanks to Microsoft, there is a way easier technique! If you google for windows exploitation, the huge part of results will contain a SEH keyword. Structured Exception Handling is a windows specific mechanism. I won't go over how this works here as there are plenty of great materials on internet. You can even watch a nice video [here](https://www.rapid7.com/resources/structured-exception-handler-overwrite-explained/).
But basicaly, windows programs keep a linked list of `EXCEPTION_REGISTRATION_RECORDS`. Each of these records has a pointer to next record and pointer to function responsible for handling the exception. Such function will check if it can handle the exception and if not it will pass the exception to next record. You might wonder where is this list stored. And this is crucial for us as attackers – it is stored at the stack!

So let's examine the stack right before we read the sprite name.

```
Registers:
EAX : 00000251
EBX : 00000001
ECX : 06CC5900
EDX : 0019C43C
EBP : 06CC5900
ESP : 0019C418
ESI : 06CC5900
EDI : 0019C4A0
EIP : 004DBAE3     <h3demo.buffer_overflow>


Stack:
0019C418  00000251  
0019C41C  00000000  
0019C420  02A0CA38  
0019C424  06CC5900  
0019C428  00000001  
0019C42C  00000000  
0019C430  00000251  
0019C434  0019C470  
0019C438  0059BCB7  
0019C43C  00000000  char sprite_name[96]
0019C440  00000000  
0019C444  00000000  
0019C448  00000000  
0019C44C  00000000  
[...]
0019C4A8  02AEC130  
0019C4AC  004DC716 
0019C4B0  004DC773  return to h3demo.004DC773 from h3demo.vulnerable_func
0019C4B4  06CC5900  
0019C4B8  02AEC130  
0019C4BC  02A308F0  
[...]
0019C520  00000000  
0019C524  0019C594  Pointer to SEH_Record[1]
0019C528  005AC800  
0019C52C  FFFFFFFF  
0019C530  004D66E0  
```

As `read_n_bytes_from_map` is using `__fastcall` calling convention we see, that the arguments passed to it are:

```
ecx: 0x06CC5900 (raw_map)
edx: 0x0019C43C (sprite_name buffer located on the stack)
[esp]: 0x251 (sprite_name_len)
```

## Getting control over EIP
So our goal is to overwrite SEH record. In fact we just want to overwrite the handler field. We can see above that SEH record is located at 0x0019C524. The handler field is the second field in the structure and so it is at address 0x0019C528. The sprite_name buffer starts at 0x0019C43C. So to overflow the handler we need to write: 236 (0x0019C43C - 0x0019C528) bytes.

To ease testing I've rewriten the orginal exploit to python3 as it is way easier to manipulate the payload this way.

At this point we have full control over EIP.

## Stack pivot
We do control the EIP, but the question was, what's next? We cannot just jump to our shellcode located on the stack as ASLR and DEP are both enabled. But we could try to create a ROP chain as we control the stack. But we have to increase the esp to point to our payload. Let's examine registers when execution is passed to us:

![](img/registers.png)

```
EAX : 00000000
EBX : 00000000
ECX : 42424242
EDX : 77538E90     ntdll.77538E90
EBP : 0019BE88
ESP : 0019BE68
ESI : 00000000
EDI : 00000000
EIP : 42424242
```

The ESP is at 0x0019BE68 and we want to pivot it down the stack to array we control: [0x0019C43C-...].

I've used great plugin `mona` and `Immunity Debugger` to find stack pivot suggestions.
Run `demo.exe` under `Immunity Debugger`, set workdir with command: `!mona config -set workingfolder c:\logs\%p_%i`. Then run rop command: `!mona rop` which will generate:

1) rop.txt
2) rop_chains.txt
3) rop_suggestions.txt
4) stackpivot.txt
files.

For now the interesting one is `stackpivot.txt.` We can use it to find some useful gadgets. It is really amazing. It generated over 20k possible pivots and sorted for us:

```
# stackpivot.txt
Stack pivots, minimum distance 8
-------------------------------------
Non-SafeSEH protected pivots :
------------------------------
0x00402b88 : {pivot 8 / 0x08} :  # POP ESI # POP EBX # RETN 0x0C    ** [h3demo.exe] **   |  startnull {PAGE_EXECUTE_READ}
0x00402cb4 : {pivot 8 / 0x08} :  # POP ESI # POP EBX # RETN 0x0C    ** [h3demo.exe] **   |  startnull {PAGE_EXECUTE_READ}
0x00402fdf : {pivot 8 / 0x08} :  # POP EBP # POP EBX # RETN 0x0C    ** [h3demo.exe] **   |  startnull {PAGE_EXECUTE_READ}
0x004038f7 : {pivot 8 / 0x08} :  # ADD ESP,8 # RETN 0x0C    ** [h3demo.exe] **   |  startnull {PAGE_EXECUTE_READ}
0x00403914 : {pivot 8 / 0x08} :  # ADD ESP,8 # RETN 0x0C    ** [h3demo.exe] **   |  startnull,asciiprint,ascii {PAGE_EXECUTE_READ}
0x0040398c : {pivot 8 / 0x08} :  # ADD ESP,8 # RETN 0x0C    ** [h3demo.exe] **   |  startnull {PAGE_EXECUTE_READ}
0x004039ee : {pivot 8 / 0x08} :  # ADD ESP,8 # RETN 0x0C    ** [h3demo.exe] **   |  startnull {PAGE_EXECUTE_READ}
[...]
0x0042988f : {pivot 1672 / 0x688} :  # POP EBX # ADD ESP,684 # RETN 0x04    ** [h3demo.exe] **   |  startnull {PAGE_EXECUTE_READ}
0x004298a5 : {pivot 1672 / 0x688} :  # POP EBX # ADD ESP,684 # RETN 0x04    ** [h3demo.exe] **   |  startnull {PAGE_EXECUTE_READ}
0x0054a7e3 : {pivot 1816 / 0x718} :  # ADD ESP,718 # RETN 0x04    ** [h3demo.exe] **   |  startnull {PAGE_EXECUTE_READ}
0x0054a803 : {pivot 1816 / 0x718} :  # ADD ESP,718 # RETN 0x04    ** [h3demo.exe] **   |  startnull {PAGE_EXECUTE_READ}
0x0054acb1 : {pivot 1816 / 0x718} :  # ADD ESP,718 # RETN 0x04    ** [h3demo.exe] **   |  startnull {PAGE_EXECUTE_READ}
[...]
```

## 


There are standard ways to bypass DEP on windows. Windows API provides few useful functions for this: `VirtualProtect`, `VirtualAlloc`, `SetInformationProcess`, `SetProcessDEPPolicy`.

Looking through `IAT` import api table (elf's `plt` table) in IDA I've found the `VirtualAlloc`.

