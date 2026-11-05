import { sendOtpCode } from './sms';
import type { ParsedUrlQuery } from 'querystring';

async function startOtp(params: ParsedUrlQuery) {
  await sendOtpCode(String(params.phone), newCode());
}

export async function handler(req, res) {
  const { query } = req;
  await startOtp(query);
  res.end();
}
