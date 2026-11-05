// Pins: an early-return host guard `if !is_trusted_host(&q.url) { return Err(..) }` before client.get(&q.url).send().
#[derive(Deserialize)]
struct PageQuery {
    url: String,
}

async fn relay(client: web::Data<Client>, q: web::Query<PageQuery>) -> Result<String, Box<dyn Error>> {
    if !is_trusted_host(&q.url) {
        return Err("blocked host".into());
    }
    Ok(client.get(&q.url).send().await?.text().await?)
}
