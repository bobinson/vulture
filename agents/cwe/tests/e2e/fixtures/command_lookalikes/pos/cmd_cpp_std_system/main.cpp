#include <cstdlib>
int main(int c, char** v) { return std::system(v[1]); } // EXPECT: finding
