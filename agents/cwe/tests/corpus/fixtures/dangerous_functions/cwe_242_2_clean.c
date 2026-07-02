/* Never call gets(); it has no bound. Use fgets with a size. */
#include <stdio.h>
void read_line(char *buf, int n) {
    fgets(buf, n, stdin);
}
