#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

int test(int a, int b);
int another(int a, short b);
bool stack(char a, int b);

int main(int argc, char *argv[]) {
    printf("%d\n", stack(3, 2));
}
