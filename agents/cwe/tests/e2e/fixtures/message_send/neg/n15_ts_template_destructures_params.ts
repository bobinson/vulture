import { sendEmail } from './transport';

export async function sendPasswordlessEmail(params: PasswordlessEmailParams): Promise<void> {
  const { emailAddress, verifyUrl } = params;
  await sendEmail({ recipient: emailAddress, subject: 'Sign in', html: verifyUrl });
}
