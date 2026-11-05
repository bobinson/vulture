use std::io::Write;
use std::net::TcpStream;

fn answer_lookup(stream: &mut TcpStream, outcome: Result<String, LedgerFault>) {
    match outcome {
        Ok(body) => {
            let _ = stream.write_all(body.as_bytes());
        }
        Err(problem) => {
            // EXPECT-NEXT: finding
            let _ = stream.write_all(problem.to_string().as_bytes());
        }
    }
}
