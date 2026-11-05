// CWE-78 known gap: system is hidden behind the function-like macro RUN; the preprocessor is not expanded, so argv[1] reaching it is invisible to the AST tier
#include <stdlib.h>

#define RUN(x) system(x)

int main(int argc, char **argv) {
    return RUN(argv[1]);
}
