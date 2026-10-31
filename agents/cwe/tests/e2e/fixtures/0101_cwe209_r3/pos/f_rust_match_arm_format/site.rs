struct Outcome {
    ok: bool,
    error: Option<String>,
}

fn load(id: &str) -> Outcome {
    match db::get(id) {
        Ok(_) => Outcome { ok: true, error: None },
        Err(e) => Outcome { ok: false, error: Some(e.to_string()) },
    }
}

fn load_q(id: &str) -> Outcome {
    match db::get(id) {
        Ok(_) => Outcome { ok: true, error: None },
        Err(e) => Outcome { ok: false, error: Some(format!("db failed: {e}")) },
    }
}

async fn handler(id: String) -> HttpResponse {
    let out = load(&id);
    if !out.ok {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": out.error})); // probe tp-rs-F1
    }
    let o2 = load_q(&id);
    HttpResponse::InternalServerError().json(serde_json::json!({"error": o2.error})) // EXPECT: finding tp-rs-F1-format
}
