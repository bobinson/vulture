// CWE-78 clean twin: argv form with no shell and no flag literal; argv[1] is a plain argument to ls via execlp -> none
#include <unistd.h>

int main(int argc, char **argv) {
    execlp("ls", "ls", argv[1], (char *)NULL);
    return 1;
}
