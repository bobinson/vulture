// held-out heldout_29 (CWE-918): Map.get on a per-chat history map keyed by a chat id parsed from an inbound message event
export function parseInbound(event: InboundEvent): InboundContext {
  return {
    chatId: event.message.chat_id,
    threadKind: event.message.thread_kind,
    content: event.message.content,
  };
}

export async function handleInbound(params: {
  event: InboundEvent;
  threadLogs?: Map<string, LogEntry[]>;
  maxTurns: number;
}): Promise<unknown> {
  const { event, threadLogs, maxTurns } = params;
  let ctx = parseInbound(event);
  const isGroup = ctx.threadKind === "group";
  const sender = await lookupSenderName(ctx);
  if (sender.name) ctx = { ...ctx, senderName: sender.name };

  const logKey = isGroup ? ctx.chatId : undefined;
  const priorTurns =
    isGroup && logKey && maxTurns > 0 && threadLogs
      ? (threadLogs.get(logKey) ?? []).map((entry) => ({
          sender: entry.sender,
          body: entry.body,
          timestamp: entry.timestamp,
        }))
      : undefined;

  return { body: ctx.content, history: priorTurns };
}
