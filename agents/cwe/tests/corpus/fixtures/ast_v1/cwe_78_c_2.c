// CWE-78 shape: a line read from the terminal by readline reaches popen through one assignment (stdin source -> command sink)
#include <stdio.h>
#include <stdlib.h>
#include <readline/readline.h>

int main(void) {
    char *cmd = readline("cmd> ");
    FILE *out = popen(cmd, "r");
    return out == NULL;
}
