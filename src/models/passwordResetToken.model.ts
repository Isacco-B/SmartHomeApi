import { Schema, model } from "mongoose";

interface IPasswordResetToken {
  token: string;
  email: string;
  expires: Date;
}

const passwordResetTokenSchema = new Schema<IPasswordResetToken>(
  {
    token: {
      type: String,
      required: [true, "Token is required"],
      unique: true,
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
    },
    expires: {
      type: Date,
      required: [true, "Expires is required"],
    },
  },
  { timestamps: true }
);

passwordResetTokenSchema.index({ updatedAt: 1 }, { expireAfterSeconds: 300 });

const PasswordResetToken = model<IPasswordResetToken>(
  "PasswordResetToken",
  passwordResetTokenSchema
);

export default PasswordResetToken;
