#include <stdlib.h>
#include <string.h>
char *slurp(int fd) {
    char *acc = malloc(1);
    size_t len = 0;
    char tmp[512];
    while (1) {
        long got = recv(fd, tmp, sizeof tmp, 0);
        if (got <= 0) break;
        // EXPECT-NEXT: finding pointer declared outside the loop, grown per receive
        acc = realloc(acc, len + got);
        memcpy(acc + len, tmp, got);
        len += got;
    }
    return acc;
}
