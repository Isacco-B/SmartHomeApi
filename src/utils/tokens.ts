import { v4 as uuidv4 } from "uuid";
import { getVerificationTokenByEmail } from "../data/verificationToken";
import { getPasswordResetTokenByEmail } from "../data/passwordResetToken";
import VerificationToken from "../models/verificationToken.model";
import PasswordResetToken from "../models/passwordResetToken.model";

export async function generateVerificationToken(email: string) {
  const token = uuidv4();
  const expires = new Date(new Date().getTime() + 300 * 1000); // 5 minutes

  const existingToken = await getVerificationTokenByEmail(email);

  if (existingToken) {
    await VerificationToken.deleteOne({
      _id: existingToken.id,
    });
  }

  const verificationToken = new VerificationToken({
    token,
    email,
    expires,
  });

  await verificationToken.save();

  return verificationToken;
}

export async function generatePasswordResetToken(email: string) {
  const token = uuidv4();
  const expires = new Date(new Date().getTime() + 300 * 1000); // 5 minutes

  const existingToken = await getPasswordResetTokenByEmail(email);

  if (existingToken) {
    await PasswordResetToken.deleteOne({
      _id: existingToken.id,
    });
  }

  const passwordResetToken = new PasswordResetToken({
    token,
    email,
    expires,
  });

  await passwordResetToken.save();

  return passwordResetToken;
}
