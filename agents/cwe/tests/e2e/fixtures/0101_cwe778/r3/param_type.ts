// Feature 0101, CWE-778 Concept A (RED round 2, R2-8). An arrow inside a
// parameter's TYPE (`onDone: (r: Row) => void`) does not make the method line a
// call that takes a callback: the method is the routine, and the class name
// above it is not part of its window. Every identifier is invented.
export class SessionPanel {
  render(onDone: (r: Row) => void) {
    try {
      this.table.paint(this.rows);
    } catch (e) { // EXPECT: clean
      return { ok: false, error: e };
    }
  }

  repaint(onDone: OnDone) {
    try {
      this.table.paint(this.rows);
    } catch (e) { // EXPECT: clean
      return { ok: false, error: e };
    }
  }
}
