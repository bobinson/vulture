// Pins: Command::new("ls").arg(&q.dir).output() with q external; argv form with no shell, so no command row through the builder chain.
#[derive(Deserialize)]
struct DirQuery {
    dir: String,
}

async fn dir_listing(q: web::Query<DirQuery>) -> std::io::Result<Vec<u8>> {
    Ok(Command::new("ls").arg(&q.dir).output()?.stdout)
}
