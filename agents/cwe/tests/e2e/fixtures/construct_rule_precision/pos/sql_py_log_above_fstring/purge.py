def purge(cur, uid, log):
    log.info("deleting %s", uid)
    q = f"DELETE FROM users WHERE id = {uid}"  # EXPECT: finding
    log.info("built")
    log.info("running")
    log.info("now")
    cur.execute(q)
