// Const and static initialisers are evaluated at compile time.
const TOTAL: usize = 4096;
const SHARDS: usize = 8;
// EXPECT-NEXT: clean
const PER_SHARD: usize = TOTAL / SHARDS;
// EXPECT-NEXT: clean
pub static HALF_SHARD: usize = PER_SHARD / SHARDS;
