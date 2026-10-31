import { writeErr } from "./http";
export async function h(req, res) {
  try { await work(); } catch (err) {
    logger.error(err);
    writeErr(res, 500, "internal error"); // EXPECT: clean literal-message
  }
}
