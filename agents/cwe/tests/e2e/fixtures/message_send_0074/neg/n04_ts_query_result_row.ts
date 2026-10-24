import { sendShippedEmail } from './mail';
import type { GetOrderByIdQuery } from './generated';

async function notifyRecipient(order: GetOrderByIdQuery["order"]): Promise<boolean> {
  const to = order.customer.email;
  return sendShippedEmail({ to, orderId: order.id });
}

export async function deliver(order: GetOrderByIdQuery["order"]) {
  return notifyRecipient(order);
}
