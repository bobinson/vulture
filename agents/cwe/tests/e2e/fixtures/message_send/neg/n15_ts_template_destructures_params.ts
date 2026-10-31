import { sendEmail } from './transport';

export async function send_passwordless_email(params: PasswordlessEmailParams): Promise<void> {
  const { emailAddress, verifyUrl } = params;
  await sendEmail({ recipient: emailAddress, subject: 'Sign in', html: verifyUrl });
}
