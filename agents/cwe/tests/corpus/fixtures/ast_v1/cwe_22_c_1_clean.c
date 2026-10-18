// CWE-22 clean twin: argv[1] is wrapped in basename before it reaches fopen, a basename sanitizer on the only flow -> decline
#include <libgen.h>
#include <stdio.h>

int main(int argc, char **argv) {
    FILE *f = fopen(basename(argv[1]), "r");
    return f == NULL;
}
