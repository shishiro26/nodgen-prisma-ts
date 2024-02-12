import express from "express";
const router = express.Router();
import {
  login,
  logout,
  updatePassword,
  register,
  userInfo,
  refreshToken,
  updateImage,
} from "../controllers/User.controllers";
import { verifyAccessToken } from "../utils/GenerateToken";
import multer from "multer";

const storage = multer.memoryStorage();
const upload = multer({ storage });

router.post("/register", register);
router.post("/login", login);
router.post("/logout", verifyAccessToken, logout);
router.patch("/updatePwd/:id", verifyAccessToken, updatePassword);
router.get("/userInfo/:id", verifyAccessToken, userInfo);
router.post("/refresh-token", refreshToken);
router.post(
  "/updateImage/:id",
  upload.single("image"),
  updateImage
);

export default router;
