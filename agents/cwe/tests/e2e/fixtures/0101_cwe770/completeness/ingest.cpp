std::vector<std::string> slurp(std::istream& sock_stream) {
    std::vector<std::string> v;
    std::string line;
    while (std::getline(sock_stream, line)) {
        // EXPECT-NEXT: finding cpp getline
        v.push_back(line);
    }
    return v;
}
