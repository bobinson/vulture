// Pins: client.get(&q.url).send() where q is a web::Query<PageQuery> extractor; get takes the field and send runs on the client carrier.
#[derive(Deserialize)]
struct PageQuery {
    url: String,
}

async fn relay(client: web::Data<Client>, q: web::Query<PageQuery>) -> Result<String, Box<dyn Error>> {
    Ok(client.get(&q.url).send().await?.text().await?)
}
