#include <stdlib.h>
#include <unistd.h>
#include <string.h>

char *slurp(int fd, size_t *len) {
    char *out = NULL;
    char buf[4096];
    ssize_t n;
    *len = 0;
    while ((n = read(fd, buf, sizeof buf)) > 0) {
        // EXPECT-NEXT: finding E32 realloc growth, the C idiom
        out = realloc(out, *len + n);
        memcpy(out + *len, buf, n);
        *len += n;
    }
    return out;
}
