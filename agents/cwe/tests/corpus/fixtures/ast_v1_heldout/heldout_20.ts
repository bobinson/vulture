// held-out heldout_20 (CWE-918): Map.delete on a member named requests, keyed by a user id, while pruning a rate window
export class RateWindow {
  private requests: Map<string, number[]> = new Map();
  private lastPrune = 0;

  constructor(
    private readonly limit = 30,
    private readonly spanMs = 60_000,
  ) {}

  allow(userId: string): boolean {
    const now = Date.now();
    const windowStart = now - this.spanMs;
    if (now - this.lastPrune > this.spanMs * 5) {
      this.prune(windowStart);
      this.lastPrune = now;
    }

    let stamps = this.requests.get(userId);
    if (stamps) {
      stamps = stamps.filter((ts) => ts > windowStart);
    } else {
      stamps = [];
    }

    if (stamps.length >= this.limit) {
      this.requests.set(userId, stamps);
      return false;
    }

    stamps.push(now);
    this.requests.set(userId, stamps);
    return true;
  }

  private prune(windowStart: number): void {
    for (const [userId, stamps] of this.requests) {
      const active = stamps.filter((ts) => ts > windowStart);
      if (active.length === 0) {
        this.requests.delete(userId);
      } else {
        this.requests.set(userId, active);
      }
    }
  }
}
