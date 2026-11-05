use std::io::{self, BufRead, BufReader, Read};
use std::net::TcpStream;

fn stdin_lines() -> Vec<String> {
    let mut out = Vec::new();
    for line in io::stdin().lines() {
        // EXPECT-NEXT: finding stdin lines
        out.push(line.unwrap());
    }
    out
}

fn locked_lines(stdin: io::Stdin) -> Vec<String> {
    let mut out = Vec::new();
    for line in stdin.lock().lines() {
        // EXPECT-NEXT: finding locked stdin lines
        out.push(line.unwrap());
    }
    out
}

fn wrapped(stream: TcpStream) -> Vec<String> {
    let reader = BufReader::new(stream);
    let mut out = Vec::new();
    for line in reader.lines() {
        // EXPECT-NEXT: finding a reader constructed over a connection
        out.push(line.unwrap());
    }
    out
}

fn wrapped_text(text: &str) -> Vec<String> {
    let reader = BufReader::new(text.as_bytes());
    let mut out = Vec::new();
    for line in reader.lines() {
        // EXPECT-NEXT: clean a reader constructed over an in-memory value
        out.push(line.unwrap());
    }
    out
}

fn while_let(mut stream: TcpStream) -> Vec<u8> {
    let mut acc = Vec::new();
    let mut tmp = [0u8; 512];
    while let Ok(n) = stream.read(&mut tmp) {
        if n == 0 { break; }
        // EXPECT-NEXT: finding read into a mutable slice
        acc.extend_from_slice(&tmp[..n]);
    }
    acc
}
