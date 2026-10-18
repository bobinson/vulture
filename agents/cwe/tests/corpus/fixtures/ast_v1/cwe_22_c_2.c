// CWE-22 shape: argv[1] reaches fopen through one assignment to the local char pointer docPath
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char *docPath = argv[1];
    FILE *f = fopen(docPath, "r");
    return f == NULL;
}
