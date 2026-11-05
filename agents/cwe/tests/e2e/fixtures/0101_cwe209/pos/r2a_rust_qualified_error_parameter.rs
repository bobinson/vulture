use std::io::Write;
use std::net::TcpStream;

fn fail_request(stream: &mut TcpStream, err: std::io::Error) {
    // EXPECT-NEXT: finding
    let _ = stream.write_all(err.to_string().as_bytes());
}
