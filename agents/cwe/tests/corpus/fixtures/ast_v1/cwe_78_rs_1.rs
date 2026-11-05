// Pins: Command::new("sh").arg("-c").arg(format!("ls {}", q.dir)): the -c flag through the .arg builder chain; format! carries q.
#[derive(Deserialize)]
struct DirQuery {
    dir: String,
}

async fn dir_listing(q: web::Query<DirQuery>) -> std::io::Result<Vec<u8>> {
    Ok(Command::new("sh").arg("-c").arg(format!("ls {}", q.dir)).output()?.stdout)
}
