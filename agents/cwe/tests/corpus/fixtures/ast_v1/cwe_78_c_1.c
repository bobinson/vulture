// CWE-78 shape: argv[1] is the command string after the flag literal "-c" in a positional execlp call whose program is sh
#include <unistd.h>

int main(int argc, char **argv) {
    execlp("sh", "sh", "-c", argv[1], (char *)NULL);
    return 1;
}
