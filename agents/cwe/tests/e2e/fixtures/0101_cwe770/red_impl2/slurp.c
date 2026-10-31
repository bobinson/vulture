#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *slurp(int fd) {
    char *data = NULL;
    size_t used = 0;
    char tmp[4096];
    ssize_t got;
    while ((got = read(fd, tmp, sizeof tmp)) > 0) {
        // EXPECT-NEXT: finding realloc per read with no ceiling
        data = realloc(data, used + got);
        memcpy(data + used, tmp, got);
        used += got;
    }
    return data;
}
