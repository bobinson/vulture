import { sendEmail } from './transport';

export async function sendWelcomeEmail(emailAddress: string, name: string): Promise<void> {
  await sendEmail({ to: emailAddress, subject: `Welcome ${name}` });
}
