#include <stdio.h>
#include <stdlib.h>

void* malloc(size_t size) {
    printf("malloc called with size: %zu\n", size);
    return NULL; // 这里只是示例，实际应调用 glibc 的 malloc
}

void free(void* ptr) {
    printf("free called with ptr: %p\n", ptr);
    // 这里只是示例，实际应调用 glibc 的 free
}
