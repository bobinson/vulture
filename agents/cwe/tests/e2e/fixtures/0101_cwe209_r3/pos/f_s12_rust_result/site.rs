use std::io::Write;
use std::net::TcpStream;

struct Outcome { error: String }

fn load(id: &str) -> Outcome {
    match store_read(id) {
        Ok(_) => Outcome { error: String::new() },
        Err(e) => Outcome { error: e.to_string() },
    }
}

fn show(stream: &mut TcpStream, id: &str) {
    let outcome = load(id);
    let _ = stream.write_all(outcome.error.as_bytes()); // EXPECT: finding tp
}
