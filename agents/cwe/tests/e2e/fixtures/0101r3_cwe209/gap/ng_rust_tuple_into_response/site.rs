async fn get() -> Response {
    match store_read().await {
        Ok(v) => v.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(), // EXPECT: clean gap-NG-tuple-response
    }
}
