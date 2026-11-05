// CWE-78 shape: argv[1] concatenated into a shell string that reaches std::system via c_str
#include <cstdlib>
#include <string>

int main(int argc, char **argv) {
    std::string dir = argv[1];
    return std::system(("ls " + dir).c_str());
}
