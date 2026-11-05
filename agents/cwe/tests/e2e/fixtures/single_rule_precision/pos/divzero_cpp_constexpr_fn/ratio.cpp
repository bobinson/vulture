// A constexpr function may also run at run time, with a run-time divisor.
// EXPECT-NEXT: finding
constexpr int ratio(int a, int b) { return a / b; }
