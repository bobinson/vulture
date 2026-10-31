// Known false positive: every throw parse() can reach is authored caller-facing
// text, but telling that apart from a leak needs the callee's throw set across
// routines; at the sink it reads exactly like a real leak.
function parse(a: unknown) {
  if (typeof a !== "string") throw new Error("payload must be text");
  return a;
}

export function upload(params: any, respond: any) {
  try {
    parse(params.content);
  } catch (err) {
    respond(false, undefined, shape("INVALID_REQUEST", String(err))); // EXPECT: finding known-gap authored-throw-closed-set
  }
}
