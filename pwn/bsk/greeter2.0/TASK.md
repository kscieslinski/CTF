# TREŚĆ greeter2.0
[Plik greeter2.0](files/greeter2.0)

[Źródło greeter2.0.c](files/greeter2.0.c)

UWAGA W tym zadaniu istotne jest założenie, że adresy w programie nie podlegają randomizacji (wyłączone zabezpieczenie ASLR - por. sekcja Założenia).

Jak wskazuje nazwa greeter2.0 jest ulepszoną wersją programu greeter, pozbawioną luki umożlwiającej przepełnienie bufora na stosie i przejęcie kontroli na wykonaniem programu.

No, niezupełnie...

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
        greet(1);

        return 0;
}
```

Mimo, że tym razem program wydaje się ograniczać rozmiar wczytywanych to zawiera błąd umożliwiający nieznaczne wyjście poza granicę bufora (w jaki sposób?). Nie spowoduje to zmiany adresu powrotu, ale możliwe będzie (częściowe) nadpisanie istotnej struktury kontrolnej - ramki stosu. Podobny pomysł ataku został opisany wiele lat temu w magazynie Phrack. Autor artykułu (klog) pokazuje, że można w ten sposób zmienić adres wierzchołka stosu i konsekwencji - adres powrotu (choć nie z funkcji, w której nastepuje przepełnienie bufora, a z funkcji, której ramka znajduje się na stosie o poziom niżej). Ogólna technika polegająca z zmianie adresu wierzchołka stosu (stack pivot) stanowi ważny instrument stosowany w eksploitacji programów.

W naszym przypadku nie kontrolujemy jednak nawet tego, w jaki sposób nadpisany zostanie wskaźnik ramki stosu. Mimo to możliwa jest jednak zmiana adresu powrotu z funkcji main i skok do wybranego przez atakującego kodu. W tym zadaniu celem jest uruchomienie procesu powłoki przez powrót do funkcji bibliotecznej execve (ogólna nazwa metody ataku zakładającej powrót do funkcji z biblioteki C to ret2libc) z podanym argumentem "/bin/sh". Zachęcamy do samodzielnego napisania skryptu generującego stosowną zawartość bufora. Należy przy tym pamiętać o przydatnej sztuczce (wskazanej już na wykładzie) z poleceniem cat sprawiającej, że po przeprowadzeniu ataku standardowe wejście uruchomionego procesu powłoki nie ulegnie zamknięciu:

```bash
$ python solver-greeter2.0.py > payload
$ cat payload - | ./greeter2.0
```
