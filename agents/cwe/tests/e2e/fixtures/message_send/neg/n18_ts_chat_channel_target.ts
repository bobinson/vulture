import { outbound } from './outbound';

export async function handleAction(ctx) {
  const to = readStringParam(ctx.params, 'to');
  const message = readStringParam(ctx.params, 'message');
  const targetChannel = to || 'general';
  await outbound.sendText({ to: targetChannel, text: message });
  return { ok: true };
}
