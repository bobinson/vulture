import { sendErr } from "./http";
export async function h(req, res) {
  try { await work(); } catch (err) {
    sendErr(res, 500, err.message); // EXPECT: finding tp-C1-send-err
  }
}
