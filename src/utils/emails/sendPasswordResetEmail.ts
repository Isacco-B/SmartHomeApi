import { sendEmail } from "../helpers";

export const sendPasswordResetEmail = async (to: string, token: string) => {
  const resetLink = `http://localhost:3000/api/auth/new-password/${token}`;
  const text = `Please click on the following link to reset your password: ${resetLink}`;
  const html = `<p>Click <a href="${resetLink}">here</a> to reset your password</p>`;

  await sendEmail({
    to,
    subject: "Reset your password",
    text,
    html,
  });
};
