// Pins: the sink arm itself reads Path::new(&name).file_name(), so fs::read_to_string never sees the raw query field in any arm.
#[derive(Deserialize)]
struct DocQuery {
    file: String,
    mode: String,
}

async fn show_doc(q: web::Query<DocQuery>) -> std::io::Result<String> {
    let mut name = q.file.clone();
    match q.mode.as_str() {
        "leaf" => name = Path::new(&q.file).file_name().unwrap_or_default().to_string_lossy().into_owned(),
        _ => return fs::read_to_string(Path::new(&name).file_name().unwrap_or_default()),
    }
    Ok(name)
}
