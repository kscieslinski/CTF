# Game (pwn, bsk, integer_overflow)

### Notes
- source code given: yes
- binary given: yes

### Enumeration
First lets check the protections.
![](img/protection.png)  

As we can see the binary hasn't been compiled as PIE. This means that if we gain control over _\$eip_ we can then jump to a function of our choice.

As to the code, we could easly spot a missing check when prompt to pick an action:
![](img/action.png)

```c
int read_action() {
	int action_no;
	while (1) {
		printf("Select action:\n1. Attack\n"
			   "2. Heal yourself\n");
		if (scanf("%d", &action_no) > 0 && action_no <= (int) ACTIONS_SIZE) {
			break;
		}
		getchar();
	}

	return action_no - 1;
}
```

As you can see, the attacker can provide a negative number.