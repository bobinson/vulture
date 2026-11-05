#include <vector>
void pump(int fd) {
    char buf[512];
    while (true) {
        long got = recv(fd, buf, sizeof buf, 0);
        if (got <= 0) { break; }
        std::vector<char> frame = std::vector<char>();
        // EXPECT-NEXT: clean scoped template type, declared in the body
        frame.push_back(buf[0]);
        handle(frame);
    }
}
