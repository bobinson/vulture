// CWE-78 shape: argv[1] passed to a same-file helper whose parameter is concatenated into the std::system command; sink inside the callee, call site in main
#include <cstdlib>
#include <string>

static int countLines(const std::string &name) {
    return std::system(("wc -l " + name).c_str());
}

int main(int argc, char **argv) {
    return countLines(argv[1]);
}
