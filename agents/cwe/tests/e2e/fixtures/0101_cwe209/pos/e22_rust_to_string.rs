fn h(mut stream: TcpStream) {
    if let Err(e) = run() {
        // EXPECT-NEXT: finding  rust to string
        stream.write_all(e.to_string().as_bytes()).unwrap();
    }
}
