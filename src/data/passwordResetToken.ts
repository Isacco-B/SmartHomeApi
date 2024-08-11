import PasswordResetToken from "../models/passwordResetToken.model";

export async function getPasswordResetTokenByEmail(email: string) {
  try {
    const passwordResetToken = PasswordResetToken.findOne({ email });
    return passwordResetToken;
  } catch (error) {
    return null;
  }
}

export async function getPasswordResetTokenByToken(token: string) {
  try {
    const passwordResetToken = PasswordResetToken.findOne({ token });
    return passwordResetToken;
  } catch (error) {
    return null;
  }
}
