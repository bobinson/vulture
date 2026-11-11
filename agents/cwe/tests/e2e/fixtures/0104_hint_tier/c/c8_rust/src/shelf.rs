use std::path::{Path, PathBuf};

const ROOT: &str = "/srv/app/shelf";

/// The on-disk path of a shelved file, if there is one.
pub fn lookup(file_name: &str) -> Option<PathBuf> {
    let candidate = Path::new(ROOT).join(file_name);
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}
