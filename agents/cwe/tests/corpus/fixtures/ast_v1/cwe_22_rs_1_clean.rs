// Pins: name = Path::new(&q.file).file_name() (the file_name method on a Path::new result strips directories) before join and fs::read_to_string.
const ROOT_DIR: &str = "/srv/docs";

#[derive(Deserialize)]
struct DocQuery {
    file: String,
}

async fn show_doc(q: web::Query<DocQuery>) -> std::io::Result<String> {
    let name = Path::new(&q.file).file_name().unwrap_or_default();
    fs::read_to_string(Path::new(ROOT_DIR).join(name))
}
