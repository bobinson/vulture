import { sendWelcomeEmail } from './mail';
import { requireValidHookSecret } from './guards';
import type { GetOrdersByCustomerQuery } from './generated';

async function notifyFirstOrder(orders: GetOrdersByCustomerQuery): Promise<void> {
  const first = orders.orders[0];
  await sendWelcomeEmail(first.customer.email, first.id);
}

export default async function onOrderCreated(req, res) {
  if (!requireValidHookSecret(req, res)) return;
  const orders = await loadOrders(req.body.event.data.new.customerId);
  await notifyFirstOrder(orders);
  return res.status(200).json({ ok: true });
}
