import otpGenerator from "otp-generator";
import { sendMailer } from "../utils/SendMail";
import { Request, Response } from "express";
import { db } from "../../prisma";

export const verifyOtp = async (req: Request, res: Response) => {
  try {
    const { otp, email } = req.body;

    const verifyOTP = await db.oTP.findUnique({ where: { email, otp } });

    if (!verifyOTP) {
      throw new Error("Invalid OTP or Email");
    }

    const user = await db.user.update({
      where: { email },
      data: { isVerified: true },
    });
    if (!user) {
      throw new Error("User not found");
    }

    res.status(200).json({ message: "User verified successfully" });
  } catch (err: any) {
    console.error(err);
    if (err.message === "Invalid OTP or Email") {
      res.status(401).json({ error: err.message });
    } else if (err.message === "User not found") {
      res.status(404).json({ error: err.message });
    } else {
      res.status(500).json({ error: "Internal server error" });
    }
  }
};

/* Resending the OTP */
export const resendOtp = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const user = await db.user.findUnique({ where: { id } });
    if (!user) {
      throw new Error("User not found");
    }

    const otp = otpGenerator.generate(6, {
      digits: true,
      specialChars: false,
      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
    });

    let email = user.email;

    const existingOtp = await db.oTP.findMany({ where: { email } });

    if (existingOtp) {
      await db.oTP.deleteMany({ where: { email } });
    }
    const expirationTime = new Date();
    expirationTime.setMinutes(expirationTime.getMinutes() + 2);

    await db.oTP.create({
      data: {
        otp,
        email,
        expiresAt: expirationTime,
      },
    });
    sendMailer(email, otp, user.Username, "resendOTP");

    res.status(200).json({ message: "OTP sent successfully" });
  } catch (err: any) {
    console.error(err);
    if (err.message === "User not found") {
      res.status(404).json({ error: err.message });
    } else {
      res.status(500).json({ error: "Failed to resend OTP" });
    }
  }
};
