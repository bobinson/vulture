use actix_files::NamedFile;
use actix_web::{web, HttpRequest, Result};

use crate::shelf::lookup;

pub async fn download(req: HttpRequest) -> Result<NamedFile> {
    let name: String = req.match_info().query("name").parse().unwrap();
    let found = lookup(&name).ok_or_else(|| actix_web::error::ErrorNotFound("missing"))?;
    Ok(NamedFile::open(found)?) // EXPECT: finding check=cwe.input_validation.path_traversal
}
