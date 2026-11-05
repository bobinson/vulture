// CWE-22 shape: argv[1] joined under rootDir with the path operator '/' reaches std::filesystem::remove
#include <cstdlib>
#include <filesystem>
#include <string>

int main(int argc, char **argv) {
    std::filesystem::path rootDir = "/srv/docs";
    std::string userPath = argv[1];
    std::filesystem::path target = rootDir / userPath;
    std::filesystem::remove(target);
    return 0;
}
