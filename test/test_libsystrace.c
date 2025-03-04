#include <stdio.h>
#include <stdlib.h>

extern void init();
extern void cann_hook();

int main() {
    init();
    cann_hook();

    void* ptr = malloc(100);
    free(ptr);

    return 0;
}
