import express, { Router } from "express";
import {
  login,
  logout,
  newPassword,
  newVerification,
  register,
  reset,
} from "../controllers/auth.controller";

const router: Router = express.Router();

router.post("/sign-up", register);
router.post("/sign-in", login);
router.post("/logout", logout);
router.post("/reset", reset);
router.post("/new-password/:token", newPassword);
router.post("/new-verification/:token", newVerification);

export default router;
