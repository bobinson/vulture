// CWE-22 shape: argv[1] reaches std::ifstream in(docPath) through one assignment; the bare-identifier argument makes the stack constructor parse as a function declaration (the vexing parse)
#include <fstream>
#include <libgen.h>
#include <string>

int main(int argc, char **argv) {
    const char *docPath = argv[1];
    std::ifstream in(docPath);
    std::string s;
    in >> s;
    return 0;
}
