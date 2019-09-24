# Game (pwn, bsk, integer_overflow)

### Notes
- source code given: yes
- binary given: yes


### Goal
Make the game anounce the user's win without crashing the game.

### Enumeration
First lets check the protections.
![](img/protection.png)  

As we can see the binary hasn't been compiled as PIE. This means that if we gain control over _\$eip_ we can then jump to a function of our choice.

As to the code, we could easly spot a missing check when prompt to pick an action:

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

As we can see, the attacker can provide a negative number.

![](img/action.png)

We can see that the program first reads an action index, and then calls a function from `action_t actions[2]` array.
```c
int action_no = read_action();
human.actions[action_no](&human, &bot);
```
Let's look at a deassembled code:

![](img/call_eax.png)

We can see, that