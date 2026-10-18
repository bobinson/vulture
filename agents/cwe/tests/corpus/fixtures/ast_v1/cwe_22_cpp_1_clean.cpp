// CWE-22 clean twin: argv[1] is wrapped in basename before it reaches the std::ifstream constructor, a basename sanitizer -> decline
#include <fstream>
#include <libgen.h>
#include <string>

int main(int argc, char **argv) {
    std::string docPath = basename(argv[1]);
    std::ifstream in(docPath.c_str());
    std::string s;
    in >> s;
    return 0;
}
