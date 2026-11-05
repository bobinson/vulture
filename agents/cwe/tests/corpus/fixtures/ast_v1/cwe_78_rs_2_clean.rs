// Pins: Command::new("du").args(["-s", &q.dir]): argv array with a non-shell flag (-s is not a shell flag), so no command row.
#[derive(Deserialize)]
struct DirQuery {
    dir: String,
}

async fn dir_usage(q: web::Query<DirQuery>) -> std::io::Result<Vec<u8>> {
    Ok(Command::new("du").args(["-s", &q.dir]).output()?.stdout)
}
