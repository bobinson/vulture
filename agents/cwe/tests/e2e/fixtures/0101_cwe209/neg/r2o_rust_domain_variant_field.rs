use std::io::Write;
use std::net::TcpStream;

fn answer_quota(stream: &mut TcpStream, outcome: Result<(), QuotaFault>) {
    match outcome {
        Ok(()) => {}
        QuotaError(limit) => {
            // EXPECT-NEXT: clean  a domain variant's field is not a caught error (as a domain-typed parameter, R-C7)
            let _ = stream.write_all(limit.to_string().as_bytes());
        }
    }
}
