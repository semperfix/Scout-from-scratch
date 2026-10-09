#include <stdio.h>

int add(int a, int b) { return a + b; }

int fib(int n) {
    if (n < 2) return n;
    return fib(n-1) + fib(n-2);
}

int main(void) {
    int x = 40;
    int y = 2;
    int s = add(x, y);      // expect 42
    int f = fib(10);        // expect 55
    printf("sum=%d fib=%d\n", s, f);
    return 0;
}
