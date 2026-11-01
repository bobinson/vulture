// CWE-22 clean twin: docPath comes from getenv instead of argv; env is operator-controlled and reports for no family -> none
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char *docPath = getenv("DOC_FILE");
    FILE *f = fopen(docPath, "r");
    return f == NULL;
}
