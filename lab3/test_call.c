#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

int sum(int arr[], long count);
long add(long a, long b);
unsigned long fib(long n);
void bubbleSort(int a[], unsigned long length);
long mul(long a, long b);
void hello();

void printArr(int a[], int l) {
    putchar('[');
    for (int i = 0; i < l - 1; i++) {
        printf("%d, ", a[i]);
    }
    printf("%d]", a[l - 1]);
}

int main(int argc, char *argv[]) {
    int arr[5] = {1, 25, 3, 4, 500};
    int brr[10] = {37, 22, 63, 45, 86, 94, 73, 63, 60, 35};
    printf("sum(");
    printArr(arr, 5);
    printf(", 5) = %d\n", sum(arr, 5));
    printf("add(3, 5) = %ld\n", add(3, 5));
    for (long i = 0; i <= 15; i++) {
        printf("fib(%ld) = %lu\n", i, fib(i));
    }
    printArr(brr, 10);
    printf(" -> bubbleSort -> ");
    bubbleSort(brr, sizeof(brr)/sizeof(brr[0]));
    printArr(brr, 10);
    putchar('\n');
    printf("mul(420, 1337) = %ld\n", mul(420, 1337));
    hello();
}
