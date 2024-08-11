import User from "../models/user.model";

export async function getUserByEmail(email: string) {
  try {
    const user = await User.findOne({ email });
    return user;
  } catch (error) {
    return null;
  }
}

export async function getUserById(id: string) {
  try {
    const user = User.findById(id);
    return user;
  } catch (error) {
    return null;
  }
}
