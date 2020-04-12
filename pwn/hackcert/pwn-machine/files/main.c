#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>

#define DEBUG 1
#define MAX_TAPE_SIZE 10000
#define MAX_MOVES_COUNT 100000

typedef unsigned char tape_char;
typedef unsigned int state;

typedef struct move {
    tape_char from_tape;
    state from_state;
    tape_char to_tape;
    state to_state;
    void (*direction)(unsigned int*);
} move;

void left(unsigned int *head_position){
    (*head_position)--;
}

void right(unsigned int *head_position){
    (*head_position)++;
}

void get_moves(move moves[], int moves_count){
    // Get the transformation function aka moves
    for (int i = 0; i < moves_count; i++){
        move new_move;
        unsigned char direction;
        scanf("%hhu %d %hhu %d %hhu\n", &new_move.from_tape, &new_move.from_state, &new_move.to_tape, &new_move.to_state, &direction);
        if (!direction){
            new_move.direction = left;
        } else {
            new_move.direction = right;
        }
        moves[i] = new_move;
    }
}

void get_tape(tape_char tape[], int tape_count){
    // Get the tape characters
    for (int i = 0; i < tape_count; i++){
        scanf("%hhu", &tape[i]);
    }
}

int make_move(tape_char tape[], move moves[], state *current_state, unsigned int *head_position, int moves_count){
    // Makes one move
    for(int i=0; i<moves_count;i++){
        if (moves[i].from_tape == tape[*head_position] && moves[i].from_state == *current_state){
            printf("Tape: %d Doing move (%hhu, %d) -> (%hhu, %d)\n", *head_position, moves[i].from_tape, moves[i].from_state, moves[i].to_tape, moves[i].to_state);
            *current_state = moves[i].to_state;
            tape[*head_position] = moves[i].to_tape;

            moves[i].direction(head_position);
            return 0;
        }
    }
    return -1;
}

void print_tape(tape_char tape[], int tape_count){
    for (int i=0; i<tape_count; i++){
        printf("%hhu ", tape[i]);
    }
    printf("\n");
}


int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    unsigned int buffer_size = MAX_TAPE_SIZE * sizeof(tape_char)+MAX_MOVES_COUNT * sizeof(move);
    char *buffer = (char*)malloc(buffer_size);
    if (buffer < 0){
        puts("[E] Error, couldn't allocate memory, contact admin");
    }
#ifdef DEBUG
    else {
        printf("[D] Allocated memory at %p\n", buffer);
    }
#endif
    int m = mprotect((void*)((int)buffer & ~(4096-1)), buffer_size, PROT_READ | PROT_WRITE | PROT_EXEC);
    if (m < 0){
        printf("Couldn't run mprotect %s\n", strerror(errno));
        exit(1);
    }

    tape_char *tape = (tape_char*)buffer;
    move *moves = (move*)(buffer+MAX_TAPE_SIZE*sizeof(tape_char));

    state current_state = 0, acc_state = 0;
    unsigned int moves_count = 0, tape_count = 0, head_position = 0;

    puts("Input (𝑄, 𝚺, 𝐹):");
    scanf("%d %d %d\n", &moves_count, &tape_count, &acc_state);
    if (moves_count > MAX_MOVES_COUNT){
        printf("[E] Max amount of moves is %d\n", MAX_MOVES_COUNT);
        exit(1);
    }
    if (tape_count > MAX_TAPE_SIZE){
        printf("[E] Max amount of tape characters is %d\n", MAX_TAPE_SIZE);
        exit(1);
    }

    get_moves(moves, moves_count);
    get_tape(tape, tape_count);
    print_tape(tape, tape_count);
    
    while(current_state != acc_state){
        if (make_move(tape, moves, &current_state, &head_position, moves_count) == -1){
            printf("No transformation given current situation(%hhu, %d). Aborting.\n", tape[head_position], current_state);
            print_tape(tape, tape_count);
            exit(1);
        }
    }
    puts("Given TM accepts given input");
    print_tape(tape, tape_count);
}
