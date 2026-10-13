export async function mail() {
  try { await run(); } catch (e) {
    // EXPECT-NEXT: clean  ops alert not the requester
    await mailer.sendMail({ to: OPS, text: e.message });
  }
}
