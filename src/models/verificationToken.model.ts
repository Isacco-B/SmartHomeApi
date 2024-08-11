import { Schema, model } from "mongoose";

interface IVerificationToken {
  token: string;
  email: string;
  expires: Date;
}

const verificationTokenSchema = new Schema<IVerificationToken>(
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

verificationTokenSchema.index({ updatedAt: 1 }, { expireAfterSeconds: 300 });

const VerificationToken = model<IVerificationToken>(
  "VerificationToken",
  verificationTokenSchema
);

export default VerificationToken;
