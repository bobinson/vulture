// Pins: Command::new("sh").args(["-c", &format!("du -s {}", q.dir)]): the -c flag inside an array literal handed to the args builder.
#[derive(Deserialize)]
struct DirQuery {
    dir: String,
}

async fn dir_usage(q: web::Query<DirQuery>) -> std::io::Result<Vec<u8>> {
    Ok(Command::new("sh").args(["-c", &format!("du -s {}", q.dir)]).output()?.stdout)
}
