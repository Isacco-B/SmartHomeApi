import nodemailer from "nodemailer";
import {
  EMAIL_ADDRESS,
  EMAIL_HOST,
  EMAIL_PASSWORD,
  EMAIL_PORT,
} from "../secrets";

type EmailProps = {
  to: string;
  subject: string;
  text: string;
  html: string;
};

export async function sendEmail({
  to,
  subject,
  text,
  html,
}: EmailProps): Promise<void> {
  const transporter = nodemailer.createTransport({
    host: EMAIL_HOST,
    port: Number(EMAIL_PORT),
    secure: true,
    auth: {
      user: EMAIL_ADDRESS,
      pass: EMAIL_PASSWORD,
    },
    tls: {
      rejectUnauthorized: false,
    },
  });

  await transporter.sendMail({ to, subject, text, html, from: EMAIL_ADDRESS });
}
