const sessions = [];

function gatherBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    // EXPECT-NEXT: finding E24 event-driven body read
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
  });
}

function gatherText(req, cb) {
  let body = "";
  req.on("data", (c) => {
    // EXPECT-NEXT: finding E25 string concat in data handler
    body += c;
  });
  req.on("end", () => cb(body));
}

function track(req, res) {
  // EXPECT-NEXT: clean known-gap: module-global growth once per request, no loop (NG7) (probe:E26 module-global per request)
  sessions.push(req.body);
  res.end("ok");
}

async function lines(rl) {
  const out = [];
  for await (const line of rl) {
    // EXPECT-NEXT: finding E27 readline interface named rl
    out.push(line);
  }
  return out;
}

async function pump(reader) {
  // EXPECT-NEXT: clean known-gap: a while (true) opening mid-line after another statement (LLD 5.2.6) (probe:E28 one-line loop)
  const parts = []; while (true) { const { done, value } = await reader.read(); if (done) break; parts.push(value); }
  return parts;
}
