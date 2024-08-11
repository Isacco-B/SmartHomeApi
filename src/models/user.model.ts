import { Schema, model } from "mongoose";

interface IUser {
  name: string;
  email: string;
  emailVerified?: Date;
  password: string;
}

const userSchema = new Schema<IUser>(
  {
    name: {
      type: String,
      required: [true, "Your name is required"],
    },
    email: {
      type: String,
      required: [true, "Your email address is required"],
      unique: true,
    },
    emailVerified: {
      type: Date,
    },
    password: {
      type: String,
      required: [true, "Your password is required"],
    },
  },
  { timestamps: true }
);

const User = model<IUser>("User", userSchema);
export default User;
