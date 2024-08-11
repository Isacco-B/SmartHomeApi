import { sendEmail } from "../helpers";

export const sendVerificationEmail = async (to: string, token: string) => {
  const confirmLink = `http://localhost:3000/api/auth/new-verification/${token}`;
  const text = `Please click on the following link to verify your email: ${confirmLink}`;
  const html = `<p>Click <a href="${confirmLink}">here</a> to verify your email</p>`;

  await sendEmail({
    to,
    subject: "Confirm your email",
    text,
    html,
  });
};
