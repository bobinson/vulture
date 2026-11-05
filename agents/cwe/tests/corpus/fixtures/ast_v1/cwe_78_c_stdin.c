// CWE-78 known gap: a line read from stdin into buf by fgets reaches system; a stdin read through an output buffer is not modelled, so the AST tier sees no external origin at the sink
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char buf[256];
    fgets(buf, sizeof buf, stdin);
    return system(buf);
}
