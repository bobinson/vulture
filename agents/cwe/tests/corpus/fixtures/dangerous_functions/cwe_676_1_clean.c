#include <string.h>
void copy_name(char *dst, const char *src, size_t n) {
    strncpy(dst, src, n);
    dst[n - 1] = 0;
}
