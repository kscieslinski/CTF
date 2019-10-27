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

|calc ram|    |calc ram|
|--------|    |--------|
|        |    |        |
|        |    |        |
|        |    |        |
|        |    |        |


To read: +7

|calc ram|    |calc ram|
|--------|    |--------|
|        |    |        |
|        |    |        |
|        |    |        |
|   8    |    |        |


To read: 7
|calc ram|    |calc ram|
|--------|    |--------|
|        |    |        |
|        |    |        |
|        |    |        |
|   8    |    |   +    |


To read: '/0'
|calc ram|    |calc ram|
|--------|    |--------|
|        |    |        |
|        |    |        |
|   7    |    |        |
|   8    |    |   +    |

To read: 
|calc ram|    |calc ram|
|--------|    |--------|
|        |    |        |
|        |    |        |
|        |    |        |
|   15   |    |        |

## Exploit
