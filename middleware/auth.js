const { check, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const User = require('../models/users'); // Adjust the path to your User model
const {userSession} = require('../models/userloginlog');
require('dotenv').config();


const getClientIP = (req) => {
    const forwarded = req.headers['x-forwarded-for']; // Check for forwarded IPs
    console.log(forwarded);
    const userIP = forwarded ? forwarded.split(',')[0] : req.connection.remoteAddress; // If none, fallback to remoteAddress
    console.log(userIP);
    return userIP;
  };
const loginValidation = [
  check('email', 'Please provide a valid email').isEmail(),
  check('password', 'Password must be at least 6 characters long').isLength({ min: 6 }),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];
const emailverifier = [
  check('email', 'Please provide a valid email').isEmail(),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];
const authenticateGuestToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
  console.log(token,process.env.GUEST_JWT_SECRET);
    if (!token) return res.status(401).json({ message: 'No token provided' });
  
    try {
      // Verify token
      const decoded = jwt.verify(token, process.env.GUEST_JWT_SECRET);
  
      // If token is for a guest user, allow access but restrict features
      if (decoded.isGuest) {
        req.guest = { id: decoded.id, isGuest: decoded.isGuest };
        console.log('Guest Token verified',decoded.id);
        next();
      } else {
        return res.status(403).json({ message: 'Unauthorized, guest access only' });
      }
    } catch (error) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
  };
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    console.log(authHeader);
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token provided' });
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      console.log('DEcode:',decoded)
      // Check if the session exists in the database
      const session = await userSession.findOne({ token });
      if (!session) return res.status(401).json({ message: 'Session expired or user logged out' });
      // Attach user data to request object
      req.user = decoded; // or fetch the user from DB based on decoded.id
      next();
    } catch (err) {
      return res.status(403).json({ message: 'Token is invalid or expired' });
    }
  };

module.exports = { loginValidation , authenticateToken,getClientIP,authenticateGuestToken,emailverifier};