#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

int main() {
    // for (size_t i = 0; i < 32; i++)
    //     elems[i] = -1;
    int n;
    printf("number of elements\n");
    scanf("%d", &n);

    int elems[n];
    for (size_t i = 0; i < n; i++)
        elems[i] = i + 1;

    printf("elms = [ ");
    for (size_t i = 0; i < n; i++)
        printf("%d ", elems[i]);

    printf("]\n");

    return 0;
}