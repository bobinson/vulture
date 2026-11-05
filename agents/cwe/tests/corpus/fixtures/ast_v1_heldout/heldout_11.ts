// held-out heldout_11 (CWE-918): Set.delete keyed by a payload field, after a membership check on a set the host holds
type Host = { pendingRefreshes: Set<string> };
type EventPayload = { taskId?: string; sessionKey?: string };

function onTerminalEvent(host: Host, payload: EventPayload | undefined, state: string) {
  if (state !== "final" && state !== "error" && state !== "aborted") {
    return;
  }
  resetStream(host);
  const taskId = payload?.taskId;
  if (!taskId || !host.pendingRefreshes.has(taskId)) {
    return;
  }
  host.pendingRefreshes.delete(taskId);
  if (state === "final") {
    void reloadList(host);
  }
}

export function onChatEvent(host: Host, payload: EventPayload | undefined) {
  const state = classifyEvent(host, payload);
  onTerminalEvent(host, payload, state);
}
