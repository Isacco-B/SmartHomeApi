import VerificationToken from "../models/verificationToken.model";

export async function getVerificationTokenByEmail(email: string) {
  try {
    const verificationToken = await VerificationToken.findOne({ email });
    return verificationToken;
  } catch (error) {
    return null;
  }
}

export async function getVerificationTokenByToken(token: string) {
  try {
    const verificationToken = await VerificationToken.findOne({ token });
    return verificationToken;
  } catch (error) {
    return null;
  }
}
