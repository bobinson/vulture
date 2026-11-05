// What a live region (role="alert", aria-live) would announce again: the text
// of every node added to it, and of every text node changed in place. A
// region whose content is left untouched is not re-announced, however often
// it re-renders. The returned function hands back what changed since its
// previous call.
export function watchAnnouncements(region: Element): () => string[] {
  let delivered: MutationRecord[] = [];
  const observer = new MutationObserver((records) => delivered.push(...records));
  observer.observe(region, { childList: true, characterData: true, subtree: true });
  return () => {
    const changes = [...delivered, ...observer.takeRecords()];
    delivered = [];
    return changes.flatMap(announcedText);
  };
}

function announcedText(record: MutationRecord): string[] {
  const nodes = record.type === "characterData" ? [record.target] : Array.from(record.addedNodes);
  return nodes.map((node) => node.textContent ?? "");
}
