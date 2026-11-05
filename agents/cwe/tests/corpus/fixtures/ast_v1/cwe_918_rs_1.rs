// Pins: reqwest::get(&q.url) where q is a web::Query<PageQuery> extractor param; get is a sink with no browser gate outside JS/TS.
#[derive(Deserialize)]
struct PageQuery {
    url: String,
}

async fn preview(q: web::Query<PageQuery>) -> Result<String, Box<dyn Error>> {
    Ok(reqwest::get(&q.url).await?.text().await?)
}
