use std::io::Write;
use std::net::TcpStream;

struct Outcome { ok: bool, error: String }
impl Outcome { fn failed(msg: String) -> Self { Outcome { ok: false, error: msg } } }

fn load(id: &str) -> Outcome {
    match store_read(id) {
        Ok(_) => Outcome { ok: true, error: String::new() },
        Err(e) => Outcome::failed(e.to_string()),
    }
}

fn show(stream: &mut TcpStream, id: &str) {
    let outcome = load(id);
    let _ = stream.write_all(outcome.error.as_bytes()); // EXPECT: finding tp-factory
}
