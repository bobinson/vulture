import type { ParsedUrlQuery } from 'querystring';
import { sendOtpCode } from './sms';

async function startOtp(params: ParsedUrlQuery) {
  const phone = String(params.phone);
  await sendOtpCode(phone, newCode());
}

export async function handler(req, res) {
  await startOtp(req.query);
  res.end();
}
