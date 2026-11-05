#include <cstddef>

// constexpr variables are initialised at compile time.
constexpr std::size_t kTotal = 4096;
constexpr std::size_t kPages = 16;
// EXPECT-NEXT: clean
constexpr std::size_t kPerPage = kTotal / kPages;

struct Grid {
    static constexpr int kWidth = 64;
    static constexpr int kCells = 8;
    // EXPECT-NEXT: clean
    static constexpr int kCellWidth = kWidth / kCells;
};
