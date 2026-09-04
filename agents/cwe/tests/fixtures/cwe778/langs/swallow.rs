fn a(p: &str) -> Result<(), E> {
    let f = read(p)?;                       // propagates - MUST NOT fire
    let g = read(p).unwrap();               // panics loudly - MUST NOT fire
    let h = read(p).expect("needed");       // panics loudly - MUST NOT fire
    if let Err(e) = write(p) {
        return;
    }
    if let Err(e) = write(p) {
        tracing::error!("write failed: {e}");
    }
    match write(p) {
        Ok(v) => v,
        Err(e) => {
            0
        }
    }
    write(p).ok();
    Ok(())
}
