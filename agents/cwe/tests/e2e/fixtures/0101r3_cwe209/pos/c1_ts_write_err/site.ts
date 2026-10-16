import { writeErr } from "./http";
export async function h(req, res) {
  try { await work(); } catch (err) {
    writeErr(res, 500, err.message); // EXPECT: finding tp-C1-write-err
  }
}
