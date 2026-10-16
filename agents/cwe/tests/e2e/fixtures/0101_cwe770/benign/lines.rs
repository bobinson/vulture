use std::io::{BufRead, BufReader, Read};

pub fn first(reader: BufReader<std::net::TcpStream>, max_lines: usize) -> Vec<String> {
    let mut out = Vec::new();
    for line in reader.lines().take(max_lines) {
        // EXPECT-NEXT: clean F25 .take(n) caps the iterator
        out.push(line.unwrap());
    }
    out
}

pub fn config(path: &str) -> Vec<String> {
    let f = std::fs::File::open(path).unwrap();
    let reader = BufReader::new(f);
    let mut out = Vec::new();
    for line in reader.lines() {
        // EXPECT-NEXT: clean F26 local config file reader
        out.push(line.unwrap());
    }
    out
}
