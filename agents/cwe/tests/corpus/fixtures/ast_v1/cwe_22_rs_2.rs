// Pins: one match arm rebinds name to its Path::new(..).file_name() while a sibling arm passes the raw name to fs::read_to_string (sanitizer and sink in different arms).
#[derive(Deserialize)]
struct DocQuery {
    file: String,
    mode: String,
}

async fn show_doc(q: web::Query<DocQuery>) -> std::io::Result<String> {
    let mut name = q.file.clone();
    match q.mode.as_str() {
        "leaf" => name = Path::new(&q.file).file_name().unwrap_or_default().to_string_lossy().into_owned(),
        _ => return fs::read_to_string(&name),
    }
    Ok(name)
}
