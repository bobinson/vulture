// CWE-78 clean twin: the concatenated part is a string constant, so only constants reach std::system -> none
#include <cstdlib>
#include <string>

int main(int argc, char **argv) {
    std::string dir = "/srv/data";
    return std::system(("ls " + dir).c_str());
}
