use std::io::Write;
use std::net::TcpStream;

fn answer_sync(stream: &mut TcpStream, outcome: Result<(), LedgerFault>) {
    if let Err(problem) = outcome {
        // EXPECT-NEXT: finding
        let _ = stream.write_all(problem.to_string().as_bytes());
    }
}
