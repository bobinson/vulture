fn h(res: &mut Resp) {
    match svc.load() {
        // EXPECT-NEXT: finding  the Err(e) arm binds the error; format! carries it (known gap closed in round 2)
        Err(e) => { res.write(format!("failed: {}", e)); }
        Ok(_) => {}
    }
}
