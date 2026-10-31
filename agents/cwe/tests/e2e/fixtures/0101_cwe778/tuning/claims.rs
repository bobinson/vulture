// Feature 0101 tuning fixture (round-0 held-out, now tuning): invented identifiers.
impl Store {
    fn claims_for(&mut self, raw: &str) -> Option<Claims> {
        match jsonwebtoken::decode::<Claims>(raw, &self.key, &self.validation) {
            Ok(data) => Some(data.claims),
            Err(_) => { // EXPECT: finding
                self.set_failed(true);
                None
            }
        }
    }
}
