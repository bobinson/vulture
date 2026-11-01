// CWE-22 clean twin: argv[1] is wrapped in basename before it reaches the vexing-parse std::ifstream in(docPath), a basename sanitizer -> decline
#include <fstream>
#include <libgen.h>
#include <string>

int main(int argc, char **argv) {
    const char *docPath = basename(argv[1]);
    std::ifstream in(docPath);
    std::string s;
    in >> s;
    return 0;
}
