// CWE-78 clean twin: the same-file helper is called with a string constant, so only constants reach std::system inside it -> none
#include <cstdlib>
#include <string>

static int countLines(const std::string &name) {
    return std::system(("wc -l " + name).c_str());
}

int main(int argc, char **argv) {
    return countLines("notes.txt");
}
