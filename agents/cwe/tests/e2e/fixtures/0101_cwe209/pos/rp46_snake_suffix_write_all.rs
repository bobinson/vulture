fn h(mut stream: TcpStream) {
    if let Err(e) = run() {
        // EXPECT-NEXT: finding  snake suffix write all
        stream.write_all(e.to_string().as_bytes()).unwrap();
    }
}
