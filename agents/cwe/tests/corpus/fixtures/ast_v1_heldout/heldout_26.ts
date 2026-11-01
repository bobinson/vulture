// held-out heldout_26 (CWE-22): the definition of a method named readFile taking a params object; its body delegates under another name
export class FallbackSearch {
  private mainDown = false;
  private lastError?: string;

  constructor(private readonly deps: { primary: SearchStore }) {}

  async readFile(params: { relPath: string; from?: number; lines?: number }) {
    if (!this.mainDown) {
      return await this.deps.primary.loadEntry(params);
    }
    const fallback = await this.openBackup();
    if (fallback) {
      return await fallback.loadEntry(params);
    }
    throw new Error(this.lastError ?? "store read unavailable");
  }
}
