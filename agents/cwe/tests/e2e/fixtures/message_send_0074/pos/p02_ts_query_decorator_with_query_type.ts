import { sendOtpCode } from './sms';

export class LinkController {
  async start(@Query() dto: StartLinkQuery) {
    const phone = dto.phone;
    await sendOtpCode(phone, newCode());
    return { accepted: true };
  }
}
