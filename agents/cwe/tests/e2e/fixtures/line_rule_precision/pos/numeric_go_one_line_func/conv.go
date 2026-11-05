package conv

func audit(name string) {}

func conv(n uint64) int { return int(n) } // EXPECT: finding
