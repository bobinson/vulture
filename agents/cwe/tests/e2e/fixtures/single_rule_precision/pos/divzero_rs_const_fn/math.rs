// A const fn may also run at run time, with a run-time divisor.
// EXPECT-NEXT: finding
pub const fn per_shard(total: usize, shards: usize) -> usize { total / shards }
