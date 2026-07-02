fn first(v: &[u8]) -> u8 {
    unsafe { *v.get_unchecked(0) }
}
