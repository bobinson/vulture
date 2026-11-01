// Pins: fs::read_to_string(Path::new(ROOT_DIR).join(name)) where name = &q.file and q is a web::Query<DocQuery> extractor param.
const ROOT_DIR: &str = "/srv/docs";

#[derive(Deserialize)]
struct DocQuery {
    file: String,
}

async fn show_doc(q: web::Query<DocQuery>) -> std::io::Result<String> {
    let name = &q.file;
    fs::read_to_string(Path::new(ROOT_DIR).join(name))
}
