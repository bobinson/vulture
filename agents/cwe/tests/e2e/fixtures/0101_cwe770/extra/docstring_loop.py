def drain_with_template(sock):
    frames = []
    while True:
        """
a column-0 string literal inside the loop body
"""
        chunk = sock.recv(4096)
        if not chunk:
            break
        # EXPECT-NEXT: finding the column-0 string interior must not end the loop walk
        frames.append(chunk)
    return frames


def urls_in_memory(ws_urls):
    seen = []
    for ws_url in ws_urls:
        # EXPECT-NEXT: clean `ws_urls` head noun is urls, not a socket
        seen.append(ws_url)
    return seen


def lines_of_text(resp):
    out = []
    for line in resp.text.splitlines():
        # EXPECT-NEXT: clean the body was already read; splitlines materialises it
        out.append(line)
    return out


def fill_sheet(ws):
    rows = []
    for row in ws:
        # EXPECT-NEXT: finding known-gap: role-name heuristic; a parameter named `ws` may be a worksheet (LLD 5.2.3)
        rows.append(row)
    return rows


def fetch_rows(cur):
    rows = []
    while True:
        row = cur.fetchone()
        if row is None:
            break
        # EXPECT-NEXT: clean known-gap: a database cursor fetch is not a pull role
        rows.append(row)
    return rows
