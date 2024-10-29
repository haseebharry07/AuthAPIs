var express = require("express");
const { body, validationResult } = require('express-validator');
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
  authenticateToken
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
// Registration route with validation
router.post('/register', 
  body('email').isEmail().withMessage('Please enter a valid email address.'),
  body('username').notEmpty().withMessage('Username is required.'),
  body('phone').notEmpty().withMessage('Phone number is required.'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long.'),
  async (req, res) => {
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
  await sendEmail(email, username, otp);
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

  // Find user by email
  const user = await User.findOne({ email });
  console.log(user);
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  // Check if OTP matches and is within the expiration time
  if (user.otpCode === otp && user.otpExpiration > Date.now()) {
    try {
      if (user.isGuest) {
        // For Guest
        await User.updateOne(
          { email },
          {
            isEmailVerified: true,
            isGuest: false, 
            tokenExpiration: null,
            otpCode: null,
            otpExpiration: null,
          }
        );
        return res.status(200).json({ message: "Guest user converted to registered user and email verified successfully" });
      } else {
        // For Reqular User
        await User.updateOne(
          { email },
          {
            isEmailVerified: true,
            otpCode: null,
            otpExpiration: null,
          }
        );
        return res.status(200).json({ message: "Email verified successfully" });
      }
    } catch (e) {
      console.error(e);
      return res.status(500).json({ message: "Server error while verifying email" });
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
  console.log("start",email,password);
 
  try {
    const user = await User.findOne({ email });
    console.log(user);
    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }
    console.log(user.isEmailVerified);
    // let msg = 'Login successful'; 
    if (!user.isEmailVerified) {
        const otp = generateOTP();
        const expirationTime = Date.now() + 10 * 60 * 1000; // OTP valid for 10 minutes
        user.otpCode = otp;
        user.otpExpiration = expirationTime;
        await user.save();
      await sendEmail(email, user.username, otp);
    //  msg = 'Email is not Verified....  To Verify Email OTP send to the user email please check thanks';
      return res.status(400).json({ message: "Email is not Verified....  To Verify Email OTP send to the user email please check thanks" });
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
    await userSession.create({
      userId: user._id,
      token: token,
      ipAddress: req.ip,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      createdAt: new Date(),
    });
    return res.status(200).json({
      status: "success",
      message: 'Login successful',
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
 *     summary: Guest Login
 *     description: Allows a user to log in as a guest and receive a temporary token with a 24-hour expiration.
 *     responses:
 *       200:
 *         description: Guest login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: success
 *                 message:
 *                   type: string
 *                   example: Guest login successful
 *                 data:
 *                   type: object
 *                   properties:
 *                     guestUser:
 *                       type: object
 *                       properties:
 *                         id:
 *                           type: string
 *                           description: Unique ID of the guest user.
 *                         isGuest:
 *                           type: boolean
 *                           description: Indicator that the user is a guest.
 *                         createdAt:
 *                           type: string
 *                           format: date-time
 *                           description: Creation timestamp of the guest user.
 *                         tokenExpiration:
 *                           type: string
 *                           format: date-time
 *                           description: Token expiration timestamp.
 *                     accessToken:
 *                       type: string
 *                       description: Access token for the guest user.
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *                   description: The current timestamp.
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
// Guest Login API
router.post("/guest-login", async (req, res) => {
  try {
    // Generate a unique guest ID
    const guestID = new mongoose.Types.ObjectId();

    // Generate a JWT token for the guest user with a 24-hour expiration
    const token = jwt.sign(
      { id: guestID, isGuest: true },
      process.env.GUEST_JWT_SECRET,
      { expiresIn: "24h" }
    );

    // Set the expiration date for the token
    const tokenExpiration = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Create a new guest user in the User collection
    const guestUser = new User({
      guestUserId: guestID,
      isGuest: true,
      createdAt: new Date(),
      accessToken: token,
      tokenExpiration: tokenExpiration,
    });

    // Save the guest user to the database
    await guestUser.save();

    // Return the guest user's data and token to the client
    return res.status(200).json({
      status: "success",
      message: "Guest login successful",
      data: {
        guestUser: {
          id: guestUser.guestUserId,
          isGuest: guestUser.isGuest,
          createdAt: guestUser.createdAt,
          tokenExpiration: guestUser.tokenExpiration,
        },
        accessToken:token,
      },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Server error" });
  }
});
/**
 * @swagger
 * /api/update-guest-user:
 *   post:
 *     summary: Update Guest User to Registered User
 *     description: Convert a guest user into a registered user by providing email, username, and password. An OTP will be sent to the provided email for verification.
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
 *                 description: The email address to register with.
 *                 example: user@example.com
 *               username:
 *                 type: string
 *                 description: The username for the registered user.
 *                 example: user123
 *               password:
 *                 type: string
 *                 format: password
 *                 description: The password for the registered user.
 *                 example: password123
 *     parameters:
 *       - in: header
 *         name: Authorization
 *         required: true
 *         schema:
 *           type: string
 *         description: Bearer token for the guest user (format: Bearer <token>).
 *     responses:
 *       200:
 *         description: OTP sent to email for verification.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: success
 *                 message:
 *                   type: string
 *                   example: OTP sent to email for verification.
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *                   description: The current timestamp.
 *       400:
 *         description: Bad request - Email or Username already exists
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Email Already Exists or UserName Already Exists
 *       404:
 *         description: Guest user not found or already registered.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Guest user not found or already registered.
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
router.post("/update-guest-user", authenticateGuestToken,async (req, res) => {
  const { email, username, password } = req.body;
  const token = req.headers.authorization.split(" ")[1]; // Token from "Bearer <token>"

  try {
    // Decode the token to get guestUserId
    const decoded = jwt.verify(token, process.env.GUEST_JWT_SECRET);
    const guestUserId = decoded.id;

    // Find the guest user by their guestUserId
    const guestUser = await User.findOne({ guestUserId, isGuest: true });
    if (!guestUser) {
      return res.status(404).json({ message: "Guest user not found or already registered." });
    }
    const existingUser = await User.findOne({email});
    if(existingUser){
      return res.status(400).json({ message: "Email Already Exists" });
    }
    const existingUsername = await User.findOne({username});
    if(existingUsername){
      return res.status(400).json({ message: "UserName Already Exists" });
    }
    // Check if the referral code exists, if provided
  // let referredBy = null;
  // if (referralCode) {
  //   const referrer = await User.findOne({ referralCode });
  //   if (!referrer) {
  //     return res.status(400).json({ message: "Invalid referral code" });
  //   }
  //   referredBy = referralCode;
  // }
  // const userReferralCode = generateReferralCode();
    const otpCode = generateOTP();
    const otpExpiration = new Date(Date.now() + 10 * 60 * 1000);
    guestUser.otpCode = otpCode;
    guestUser.otpExpiration = otpExpiration;
    guestUser.username = username;
    guestUser.email = email;
    guestUser.password = await bcrypt.hash(password, 10);
    guestUser.isGuest = false;
    // guestUser.referralCode = userReferralCode;
    // guestUser.referredBy ='null';




    await guestUser.save();

    // Send OTP to the user's email
    await sendEmail(email,username,otpCode);

    return res.status(200).json({
      status: "success",
      message: "OTP sent to email for verification.",
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Server error" });
  }
});
/**
 * @swagger
 * /api/update-email:
 *   post:
 *     summary: Update user's email address
 *     description: Allows a logged-in user to update their email address after verification.
 *     security:
 *       - bearerAuth: []
 *     tags:
 *       - Users
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               newEmail:
 *                 type: string
 *                 example: "newemail@example.com"
 *     responses:
 *       200:
 *         description: OTP sent to the new email address
 *       401:
 *         description: Unauthorized - Token is missing or invalid
 *       400:
 *         description: Bad Request - Invalid or missing data
 */

router.post('/update-email', authenticateToken, async (req, res) => {
  try {
    const { newEmail } = req.body;

    if (!newEmail) {
      return res.status(400).json({ message: 'Please provide a new email address.' });
    }

    // Retrieve logged-in user data from token
    const { email, id, isEmailVerified } = req.user;
 const user = await User.findOne({_id: id});
    // Check if the user’s current email is verified
    if (!user.isEmailVerified) {
      return res.status(400).json({ message: 'Email verification is required before updating the email address.' });
    }
    const checkNewuser = await User.findOne({newEmail});
    console.log(checkNewuser);
    // if(checkNewuser.email){
    //   return res.status(400).json({message:'Email Already Exists'});
    // }

    // Generate an OTP and send it to the new email
    const otp = generateOTP();
    const otpSent = await sendEmail(newEmail,user.username, otp);

    // Save the OTP and new email to the user’s record for verification (temporary storage, e.g., in MongoDB)
    await User.updateOne(
      { _id: id },
      { $set: { pendingNewEmail: newEmail, emailUpdateOtp: otp } }
    );

    return res.status(200).json({ message: 'OTP sent to the new email address for verification.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error.' });
  }
});

/**
 * @swagger
 * /api/verify-email-update:
 *   post:
 *     summary: Verify OTP for email update
 *     description: Confirms OTP sent to the new email and updates the email in the user's record.
 *     security:
 *       - bearerAuth: []
 *     tags:
 *       - Users
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               otp:
 *                 type: string
 *                 example: "123456"
 *     responses:
 *       200:
 *         description: Email address updated successfully
 *       400:
 *         description: Invalid OTP or request data
 */

router.post('/verify-email-update', authenticateToken, async (req, res) => {
  try {
    const { otp,newEmail } = req.body;
    const { id } = req.user;
console.log(id);
    // Retrieve user by ID and check if there's a pending email update
    const user = await User.findOne({ _id: id });
    console.log('user:',user);
    if (!user || user.emailUpdateOtp !== otp || !user.pendingNewEmail === newEmail) {
      return res.status(400).json({ message: 'Invalid OTP or Email Address' });
    }

    // Update the user’s email with the new email and clear OTP/pending data
    user.email = user.pendingNewEmail;
    user.pendingNewEmail = null;
    user.emailUpdateOtp = null;
    await user.save();

    return res.status(200).json({ message: 'Email address updated successfully.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error.' });
  }
});


// Request password reset
router.post('/reset-password', 
  body('email').isEmail().withMessage('Please enter a valid email address.'),authenticateToken,
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ status: 'error', errors: errors.array() });
    }

    const { email } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(404).json({ status: 'error', message: 'User not found.' });
    }

    // Generate OTP
    const otp = generateOTP(); // Generate a 6-digit OTP
    user.otpCode = otp;
    user.otpExpiration = Date.now() + 10 * 60 * 1000; // 10 minutes expiry
    await user.save();
    await sendEmail(user.email, user.username, otp);
    return res.status(200).json({ status: 'success', message: 'OTP sent to your email.' });
});

// Verify OTP and reset password
router.post('/reset-password/verify', 
  body('email').isEmail().withMessage('Please enter a valid email address.'),
  body('otp').isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits long.'),
  body('newPassword').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long.'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ status: 'error', errors: errors.array() });
    }
    const { email, otp, newPassword } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ status: 'error', message: 'User not found.' });
    }
    if (user.otpCode !== otp || Date.now() > user.otpExpiration) {
      return res.status(400).json({ status: 'error', message: 'Invalid or expired OTP.' });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword; 
    user.otpCode = null; 
    user.otpExpiration = null; 
    await user.save();

    return res.status(200).json({ status: 'success', message: 'Password has been reset successfully.' });
  }
);

module.exports = router;
