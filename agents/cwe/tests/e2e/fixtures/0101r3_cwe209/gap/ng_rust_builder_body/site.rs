async fn get(id: web::Path<String>) -> HttpResponse {
    match store_read(&id).await {
        Ok(v) => HttpResponse::Ok().body(v),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()), // EXPECT: clean gap-NG-builder-body
    }
}
