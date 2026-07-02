fn reinterpret(x: u32) -> i32 {
    unsafe { std::mem::transmute(x) }
}
