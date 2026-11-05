// CWE-22 shape: argv[1] passed straight to fopen as its path argument, no intermediate variable (argv source -> path sink)
#include <libgen.h>
#include <stdio.h>

int main(int argc, char **argv) {
    FILE *f = fopen(argv[1], "r");
    return f == NULL;
}
