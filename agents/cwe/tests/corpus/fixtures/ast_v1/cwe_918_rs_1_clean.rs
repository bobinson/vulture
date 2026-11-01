// Pins: an early-return host guard `if !is_trusted_host(&q.url) { return Err(..) }` on the same field before reqwest::get(&q.url).
#[derive(Deserialize)]
struct PageQuery {
    url: String,
}

async fn preview(q: web::Query<PageQuery>) -> Result<String, Box<dyn Error>> {
    if !is_trusted_host(&q.url) {
        return Err("blocked host".into());
    }
    Ok(reqwest::get(&q.url).await?.text().await?)
}
