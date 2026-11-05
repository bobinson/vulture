import { getStatus } from "./queue";
export async function handler(req, res) {
  const status = await getStatus(req.body.id);
  return res.status(200).json({
    state: status.state,
    ...(status.error ? { error: 'FAILED', message: status.error } : {}), // EXPECT: finding tp-Y
  });
}
