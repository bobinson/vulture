// CWE-78 clean twin: the popen command comes from getenv instead of the terminal; env is operator-controlled and reports for no family -> none
#include <stdio.h>
#include <stdlib.h>
#include <readline/readline.h>

int main(void) {
    char *cmd = getenv("PAGER_CMD");
    FILE *out = popen(cmd, "r");
    return out == NULL;
}
