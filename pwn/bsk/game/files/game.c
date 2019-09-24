/*
Compile with:
gcc -m32 game.c -o game
*/


#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

struct player;

typedef void (*action_t)(struct player *this_player,
	struct player *other_player);

typedef struct player {
	int hp;
 	int max_hp;
	int luck;
	int strength;
	char name[20];

	action_t actions[2]; // poor man's polymorphism
} player_t, *pplayer_t;

#define ACTIONS_SIZE (sizeof(((pplayer_t) 0)->actions) / sizeof(action_t))

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

int roll_dice(int max) {
	if (max <= 0) {
		return 0;
	}
	return rand() % max;
}

void hit(pplayer_t player, int amount) {
	player->hp = MAX(0, player->hp - amount);
}

void heal(pplayer_t player, int amount) {
	player->hp = MIN(player->hp + amount, player->max_hp);
}

void warrior_attack(pplayer_t this_player, pplayer_t other_player) {
	int amount = 10 + this_player->strength - other_player->strength;
	amount = MAX(5, amount);
	amount = MIN(amount, 20);
	printf("%s hits %s with a giantsword for %d HP\n", this_player->name, other_player->name, amount);
	hit(other_player, amount);
}

void warrior_heal(pplayer_t this_player, pplayer_t other_player) {
	int amount = roll_dice(this_player->luck / 2);
	amount = MIN(amount, 8);
	printf("%s uses a heal potion and heals himself for %d HP\n", this_player->name, amount);
	heal(this_player, amount);
}

void wizard_attack(pplayer_t this_player, pplayer_t other_player) {
	int amount = 10 + roll_dice(this_player->luck) - other_player->strength;
	amount = MAX(5, amount);
	amount = MIN(amount, 20);
	printf("%s hits %s with a fireball for %d HP\n", this_player->name, other_player->name, amount);
	hit(other_player, amount);
}

void wizard_heal(pplayer_t this_player, pplayer_t other_player) {
	int amount = roll_dice(this_player->luck / 2);
	amount = MIN(15, amount);
	printf("%s uses casts a major heal spell and heals himself for %d HP\n", this_player->name, amount);
	heal(this_player, amount);
}

void druid_attack(pplayer_t this_player, pplayer_t other_player) {
	int amount = this_player->luck - other_player->strength;
	amount = MAX(2, amount);
	amount = MIN(amount, 20);
	printf("%s hits %s with a sickle for %d HP\n", this_player->name, other_player->name, amount);
	hit(other_player, amount);
}

void druid_heal(pplayer_t this_player, pplayer_t other_player) {
	int amount = roll_dice(this_player->luck * 2);
	amount = MIN(15, amount);
	printf("%s uses draws from the power of nature to heal himself for %d HP\n", this_player->name, amount);
	heal(this_player, amount);
}

action_t warrior_class[] = {warrior_attack, warrior_heal};
action_t wizard_class[] = {wizard_attack, wizard_heal};
action_t druid_class[] = {druid_attack, druid_heal};

void set_class(pplayer_t player, action_t clazz[]) {
	memcpy(player->actions, clazz, sizeof(player->actions));
}

void set_name(pplayer_t player, const char *name) {
	strcpy(player->name, name);
}

void select_class(pplayer_t player) {
	int clazz;
	while (1) {
		puts("Select a class:\n1. Warrior\n2. Wizard\n3. Druid");
		if (scanf("%d", &clazz) > 0) {
			switch (clazz) {
				case 1:
					set_class(player, warrior_class);
					return;
				case 2:
					set_class(player, wizard_class);
					return;
				case 3:
					set_class(player, druid_class);
					return;
				default:
					break;
			}
		}
		getchar();
	}
}

#define CHARACTER_POINTS_TO_DISTRIBUTE 30

void create_player(pplayer_t player) {
	printf("Enter your name: ");
	scanf("%19s", player->name);

	select_class(player);
	
	int points_left = CHARACTER_POINTS_TO_DISTRIBUTE;

	while (1) {
		printf("Select HP pool (character points left: %d): \n", points_left);
		if (scanf("%d", &player->hp) > 0 &&
			player->hp >= 0 && player->hp <= points_left) {
			break;
		}
		getchar();
	}
	points_left -= player->hp;


	while (1) {
		printf("Pick your strength (character points left: %d): \n", points_left);
		if (scanf("%d", &player->strength) > 0 &&
			player->strength >= 0 && player->strength <= points_left) {
			break;
		}
		getchar();
	}
	points_left -= player->strength;


	player->luck = points_left;
	printf("And so your luck becomes %d\n", player->luck);	

	player->max_hp = player->hp;
}

void generate_boss(pplayer_t player) {
	int base = 30;

	// Hahahah! Good luck fighting this monster, noobz!
	player->hp = base + roll_dice(15);
	player->strength = base + roll_dice(15);
	player->luck = base + roll_dice(15);

	action_t *t[] = {warrior_class, wizard_class, druid_class};
	set_class(player, t[roll_dice(3)]);

	player->max_hp = player->hp;
}



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

void print_player(pplayer_t player) {
	printf("%s:\tHP(%d/%d) STR(%d) LCK(%d)\n",
		player->name, player->hp, player->max_hp, player->strength, player->luck);
}

#define DEAD(pplayer) ((pplayer)->hp <= 0)

int main(void) {
	player_t human, bot;

	setvbuf(stdout, NULL, _IONBF, 0);
	srand(time(NULL));
	
	create_player(&human);
	generate_boss(&bot);

	set_name(&bot, "Da BOSS");

	while (!DEAD(&human) && !DEAD(&bot)) {
		//main loop
		print_player(&human);
		print_player(&bot);

		int action_no = read_action();
		human.actions[action_no](&human, &bot);

		if (DEAD(&bot)) {
			puts("Congrats! You've defeated your mighty opponent.");
			continue;
		}

		action_no = roll_dice(ACTIONS_SIZE);
		bot.actions[action_no](&bot, &human);

		if (DEAD(&human)) {
			puts("You've been defeated. Better luck next time.");
			continue;
		}
	}

	if (DEAD(&human) && DEAD(&bot)) {
		puts("Let's call it a draw...");
	}

	return 0;
}