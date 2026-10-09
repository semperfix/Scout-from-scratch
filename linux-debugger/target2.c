#include <stdio.h>
volatile int counter = 0;
int main(void) {
    for (int i = 0; i < 5; i++) { counter += 1; }
    printf("counter=%d\n", counter);
    return 0;
}
