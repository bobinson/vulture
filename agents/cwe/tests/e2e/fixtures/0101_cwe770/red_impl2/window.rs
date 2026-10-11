use std::collections::VecDeque;
use std::io::{BufRead, Stdin};

fn pump(stdin: Stdin) {
    let mut recent = VecDeque::new();
    for line in stdin.lock().lines() {
        // EXPECT-NEXT: clean pop_front keeps the deque bounded
        recent.push_back(line.unwrap());
        recent.pop_front();
    }
}
