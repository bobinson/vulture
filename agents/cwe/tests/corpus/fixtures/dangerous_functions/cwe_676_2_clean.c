/* Historically used strcpy(); replaced with a bounded copy below. */
#include <stdio.h>
void copy_name(char *dst, const char *src, size_t n) {
    snprintf(dst, n, "%s", src);
}
