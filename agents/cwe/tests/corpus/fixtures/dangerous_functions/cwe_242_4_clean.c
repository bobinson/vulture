#include <stdio.h>
int read_line(char *buf, int n) {
    return fgets(buf, n, stdin) != 0;
}
