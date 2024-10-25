var express = require("express");
const jwt = require("jsonwebtoken");
const User = require("../models/users");
const GuestUser = require("../models/guestUser");
const { UserLoginLog, userSession } = require("../models/userloginlog");
const GuestSession = require("../models/guestSession"); // Model to store guest sessions
const mongoose = require("mongoose");
const { generateReferralCode, generateOTP } = require("../utils/core");
const sendEmail = require("../utils/sendEmail");
var passport = require("passport");
const {
  loginValidation,
  getClientIP,
  authenticateGuestToken,
  emailverifier,
} = require("../middleware/auth");
const bcrypt = require("bcrypt");
require("dotenv").config();
var router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET;

/* GET home page. */
/**
 * @swagger
 * /api/register:
 *   post:
 *     summary: Register a new user
 *     description: Register a new user by providing email, username, phone, and password. If registration is successful, an email verification link is sent to the provided email.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 description: User's email
 *                 example: user@example.com
 *               username:
 *                 type: string
 *                 description: Username of the user
 *                 example: Harry001
 *               phone:
 *                 type: string
 *                 description: User's phone number
 *                 example: 03824895759
 *               password:
 *                 type: string
 *                 description: User's password
 *                 example: password123
 *     responses:
 *       201:
 *         description: User registered successfully and verification email sent
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Please Check Your Email(Register Successfully)
 *       400:
 *         description: User already exists or input validation failed
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: User Already Exists
 *       500:
 *         description: Internal server error or email sending failure
 */
router.post("/register", async (req, res) => {
  const { email, username, phone, password, referralCode } = req.body;
  // checking user exists or not
  console.log(email, username, password);
  let user = await User.findOne({ email });
  console.log(user);
  if (user) {
    return res.status(400).json({ message: "User Already Exists" });
  }
  // Check if the referral code exists, if provided
  let referredBy = null;
  if (referralCode) {
    const referrer = await User.findOne({ referralCode });
    if (!referrer) {
      return res.status(400).json({ message: "Invalid referral code" });
    }
    referredBy = referralCode;
  }
  const otp = generateOTP();
  const expirationTime = Date.now() + 10 * 60 * 1000; // OTP valid for 10 minutes

  // Save OTP and expiration in database
  // await User.updateOne({ email: userEmail }, { otp, otpExpiration: expirationTime });
  const verificationCode = await bcrypt.hash(email, 6);
  const salt = await bcrypt.genSalt(6);
  console.log(`${salt}`);
  const hashpassword = await bcrypt.hash(password, salt);
  const userReferralCode = generateReferralCode();
  console.log(hashpassword, userReferralCode);
  user = new User({
    email,
    username,
    phone,
    referralCode: userReferralCode,
    otpCode: otp,
    otpExpiration: expirationTime,
    password: hashpassword,
    referredBy: referredBy,
    isEmailVerified: false,
    isDeleted: false,
  });
  await user.save();
  console.log(JWT_SECRET);
  // Generate JWT token for email verification
  const token = jwt.sign(
    { id: user._id, email: user.email },
    JWT_SECRET,
    { expiresIn: "1h" } // Token expires in 1 hour
  );
  // console.log(token);
  await sendEmail(email, username, otp);
  console.log(`http://localhost:3500/api/verify-email?token=${token}`);
  res
    .status(201)
    .json({ message: "Please Check Your Email(Register Successfully)" });
});
/**
 * @swagger
 * /api/verify-email:
 *   post:
 *     summary: Verify a user's email
 *     description: Verify a user's email using the OTP sent via email after registration.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 description: User's email address.
 *                 example: user@example.com
 *               otp:
 *                 type: string
 *                 description: The 6-character OTP sent to the user's email.
 *                 example: "ABC123"
 *     responses:
 *       200:
 *         description: Email verified successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Email verified successfully
 *       400:
 *         description: Invalid or expired OTP
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Invalid or expired OTP
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: User not found
 */
router.post("/verify-email", emailverifier, async (req, res) => {
  const { email, otp } = req.body;
  console.log(email, otp, "Starting Verify");
  // Find user by email and check OTP
  const user = await User.findOne({ email });
  console.log(user);
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  // Check if OTP matches and is within the expiration time
  if (user.otpCode === otp && user.otpExpiration > Date.now()) {
    try {
      // OTP is valid, mark the email as verified
      await User.updateOne(
        { email },
        { isEmailVerified: true, otpCode: null, otpExpiration: null }
      );
      return res.status(200).json({ message: "Email verified successfully" });
    } catch (e) {
      return res.status(400).json({ message: "Email is Not verify" });
    }
  }

  // Invalid or expired OTP
  res.status(400).json({ message: "Invalid or expired OTP" });
});
/**
 * @swagger
 * /api/login:
 *   post:
 *     summary: User login
 *     description: Login user with email and password. If the email is not verified or the user is deleted, appropriate messages will be returned. On successful login, a JWT token valid for 24 hours is returned, along with user information.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 description: User's email address
 *                 example: ianhaseeb01@gmail.com
 *               password:
 *                 type: string
 *                 description: User's password
 *                 example: 12345678
 *     responses:
 *       200:
 *         description: Successful login
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: success
 *                 data:
 *                   type: object
 *                   properties:
 *                     user:
 *                       type: object
 *                       properties:
 *                         email:
 *                           type: string
 *                           example: user@example.com
 *                         name:
 *                           type: string
 *                           example: John Doe
 *                         phone:
 *                           type: string
 *                           example: "1234567890"
 *                         id:
 *                           type: string
 *                           example: 60c72b2f9b1f4e3d8c456789
 *                         isEmailVerified:
 *                           type: boolean
 *                           example: true
 *                     token:
 *                       type: string
 *                       example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
 *                 timestamp:
 *                   type: string
 *                   example: 2024-10-23T07:39:48.245Z
 *       400:
 *         description: Invalid credentials, email not verified, or user does not exist
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Invalid email or password
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Server error
 */
router.post("/login", loginValidation, async (req, res) => {
  const { email, password } = req.body;
  console.log("start");
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }
    console.log(user.isEmailVerified);
    if (user.isEmailVerified == false) {
      return res.status(400).json({ message: "Email is not Verified" });
    }
    if (user.isDeleted == true) {
      return res.status(400).json({ message: "user is not exists" });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // Create JWT token valid for 24 hours
    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
      expiresIn: "24h",
    });

    // Save login log to MongoDB
    const userIP = getClientIP(req);
    console.log(userIP);
    // const userIP = req.ip; // Get user's IP address
    // const userLoginLog = new UserLoginLog({
    //   userId: user._id,
    //   ip: userIP,
    //   token,
    //   createdAt: new Date(),
    //   updatedAt: new Date(),
    // });
    // await userLoginLog.save();
    // Store the session in the database
    await userSession.create({
      userId: user._id,
      token: token,
      ipAddress: req.ip,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      createdAt: new Date(),
    });
    return res.status(200).json({
      status: "success",
      message: "Login Successful",
      data: {
        user: {
          email: user.email,
          name: user.username,
          phone: user.phone,
          id: user._id,
          isEmailVerified: user.isEmailVerified,
        },
        token,
      },
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    return res.status(500).json({ message: "Server error" });
  }
});
/**
 * @swagger
 * /api/logout:
 *   post:
 *     summary: User logout
 *     description: Logout user by invalidating the session associated with the provided JWT token.
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Successfully logged out
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Logged out successfully
 *       400:
 *         description: Session not found or already logged out
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Session not found or already logged out
 *       401:
 *         description: No token provided
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: No token provided
 *       403:
 *         description: Invalid or expired token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Invalid or expired token
 */
router.post("/logout", async (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  console.log(token);
  if (!token) return res.status(401).json({ message: "No token provided" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log(decoded._id);
    // Find and delete the session for this token
    const session = await userSession.findOneAndDelete({ token });

    if (!session)
      return res
        .status(400)
        .json({ message: "Session not found or already logged out" });

    return res.status(200).json({ message: "Logged out successfully" });
  } catch (err) {
    return res.status(403).json({ message: "Invalid or expired token" });
  }
});
/**
 * @swagger
 * /api/guest-login:
 *   post:
 *     summary: Login as a guest
 *     description: Allows a user to log in as a guest and receive a temporary JWT token.
 *     responses:
 *       200:
 *         description: Successful guest login
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: success
 *                 data:
 *                   type: object
 *                   properties:
 *                     guestUser:
 *                       type: object
 *                       properties:
 *                         id:
 *                           type: string
 *                         isGuest:
 *                           type: boolean
 *                     token:
 *                       type: string
 *       500:
 *         description: Server error
 */
// Guest Login API
router.post("/guest-login", async (req, res) => {
  try {
    // Generate a unique guest ID (could be UUID, random string, or MongoDB ObjectId)
    const guestID = new mongoose.Types.ObjectId();

    // Create a temporary guest user
    const guestUser = {
      id: guestID,
      isGuest: true,
      createdAt: new Date(),
    };

    // Save guest session in DB (optional, depends on your design)
    const newSession = GuestSession({
      guestID: guestUser.id,
      createdAt: guestUser.createdAt,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24-hour expiration
    });
    await newSession.save();

    // Generate JWT token valid for 24 hours
    const token = jwt.sign(
      { id: guestUser.id, isGuest: true },
      process.env.GUEST_JWT_SECRET,
      { expiresIn: "24h" }
    );

    // Return guest token to the client
    return res.status(200).json({
      status: "success",
      message: "Guest login successful",
      data: {
        guestUser: {
          id: guestUser.id,
          isGuest: guestUser.isGuest,
        },
        token,
      },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Server error" });
  }
});
router.post(
  "/convert-to-user",
  authenticateGuestToken,
  loginValidation,
  async (req, res) => {
    const { email, password } = req.body;
    console.log("start", email, password);
    console.log("Guest ID:", req.guest?.id);
    try {
      // Check if email already exists
      const existingUser = await User.findOne({ email });
      console.log(existingUser);
      if (existingUser) {
        return res.status(400).json({ message: "Email already registered" });
      }

      // Convert guest to registered user
      const newUser = new GuestUser({
        email,
        password: await bcrypt.hash(password, 10), // Hash password
        createdAt: new Date(),
      });
      console.log(newUser);
      console.log("Guest ID:", req.guest?.id);
      await newUser.save();

      // Optionally, delete guest session from the database

      return res.status(200).json({ message: "User registration successful" });
    } catch (error) {
      return res.status(500).json({ message: "Server error" });
    }
  }
);

/**
 * @swagger
 * /api/guest-logout:
 *   post:
 *     summary: Guest logout
 *     description: Logs out a guest user by removing or invalidating the guest session.
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Guest logged out successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Guest logged out successfully
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Server error
 */
router.post("/guest-logout", authenticateGuestToken, async (req, res) => {
  try {
    // Remove guest session from database or invalidate session
    await GuestSession.findOneAndDelete({ guestID: req.guest.id });

    return res.status(200).json({ message: "Guest logged out successfully" });
  } catch (error) {
    return res.status(500).json({ message: "Server error" });
  }
});
module.exports = router;
