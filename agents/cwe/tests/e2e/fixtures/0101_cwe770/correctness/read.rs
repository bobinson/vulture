fn read_all(stream: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut buf: Vec<u8> = vec![0; CHUNK_CAP];
        let n = stream.read(&mut buf).unwrap();
        if n == 0 { break; }
        // EXPECT-NEXT: finding generic + cap-named chunk buffer
        out.extend_from_slice(&buf[..n]);
    }
    out
}
