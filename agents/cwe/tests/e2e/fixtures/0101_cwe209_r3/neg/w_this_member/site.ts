export class LedgerView {
  error: string | null = null;
  async refresh(req: any, res: any) {
    try { await store.read(req.params.id); } catch (err) {
      this.error = err.message; // EXPECT: clean clean-W-this
    }
    res.json({ ok: this.error === null });
  }
}
