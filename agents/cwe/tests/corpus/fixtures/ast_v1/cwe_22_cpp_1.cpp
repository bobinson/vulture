// CWE-22 shape: argv[1] reaches the path argument of a std::ifstream stack constructor through one assignment, passed via c_str
#include <fstream>
#include <libgen.h>
#include <string>

int main(int argc, char **argv) {
    std::string docPath = argv[1];
    std::ifstream in(docPath.c_str());
    std::string s;
    in >> s;
    return 0;
}
