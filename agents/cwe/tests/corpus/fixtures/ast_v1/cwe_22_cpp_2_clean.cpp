// CWE-22 clean twin: userPath comes from std::getenv instead of argv; env is operator-controlled and reports for no family -> none
#include <cstdlib>
#include <filesystem>
#include <string>

int main(int argc, char **argv) {
    std::filesystem::path rootDir = "/srv/docs";
    std::string userPath = std::getenv("DOC_NAME");
    std::filesystem::path target = rootDir / userPath;
    std::filesystem::remove(target);
    return 0;
}
