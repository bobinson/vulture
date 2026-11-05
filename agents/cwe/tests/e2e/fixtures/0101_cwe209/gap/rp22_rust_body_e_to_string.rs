async fn get() -> HttpResponse {
    match run().await {
        Ok(v) => HttpResponse::Ok().json(v),
        // EXPECT-NEXT: clean  known-gap rust body e to string
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}
