#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

int test(int a, int b);
int another(int a, short b);
bool stack(char a, int b);
void print();
unsigned long setChar(int a[], int len, int idx);
void testProc(long l);

int main(int argc, char *argv[]) {
    testProc(5);
}
