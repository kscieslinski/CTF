# Greeter2.0 (pwn, bsk, ret2libc, off-by-one)

### Notes:
- source code given: yes
- binary given: yes
- staticly linked: no
- ASLR enabled: no
- canaries: no
- PIE: no

The source code:
```c
/*
Compile with:
gcc -m32 -fno-stack-protector -mpreferred-stack-boundary=2 greeter2.0.c -o greeter2.0
*/

#include <stdio.h>

void greet(int times) {
	char buffer[256];

	printf("Your name (can be long one): ");
	if (scanf("%256s", buffer) > 0) {
		while (times > 0) {
			printf("Hi %s!\n", buffer);
			times--;
		}
	}
}

int main(void) {
	//setvbuf(stdout, NULL, _IONBF, 0);
	greet(1);
	return 0;
}
```

We can easily spot that a vulnerable part of code is the _scanf_ function which will not only read 256 characters but also place a null byte \0 character at the end of loaded input. The \0 character will overflow the buffer.
![](img/buffer.png)

The question arises how can we exploit this bug. Let's see what can we override with the null character. Here is how the stack looks like before and after providing input of length >= 256.
![](img/stack0.png)

So the \0 character replaces the least significant bit of _$ebp_. Moreover new value of _$ebp_ now points into the attacker controlled buffer as: 0xffffcd00 belongs to [0xffffcc7c, 0xffffcd7c] range.
I have found on internet a really [good explanation](https://sploitfun.wordpress.com/2015/06/07/off-by-one-vulnerability-stack-based-2/) on how to exploit such vulnerability.