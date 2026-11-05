fn read_all(stream: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        // EXPECT-NEXT: finding H2 (held-out)
        out.extend_from_slice(&buf[..n]);
    }
    out
}

fn copy(v: &Vec<u32>) -> Vec<u32> {
    let mut out = Vec::new();
    for x in v.iter() {
        // EXPECT-NEXT: clean N17 (held-out)
        out.push(*x);
    }
    out
}
