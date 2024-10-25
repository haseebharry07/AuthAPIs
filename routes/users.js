var express = require('express');
var router = express.Router();
const User = require('../models/users');
const {authenticateToken} = require('../middleware/auth'); // Path to the middleware

/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('respond with a resource');
});
// Protected route: User Profile
// User profile route
/**
 * @swagger
 * /users/user-details:
 *   get:
 *     summary: Retrieve user details
 *     description: Get the authenticated user's details such as email, username, phone, and email verification status.
 *     security:
 *       - bearerAuth: []
 *     tags:
 *       - Users
 *     responses:
 *       200:
 *         description: Successfully retrieved user details
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
 *                         username:
 *                           type: string
 *                           example: Harry001
 *                         phone:
 *                           type: string
 *                           example: 03824895759
 *                         id:
 *                           type: string
 *                           example: 6717a3cae9197edcae68b98a
 *                         isEmailVerified:
 *                           type: boolean
 *                           example: true
 *                 timestamp:
 *                   type: string
 *                   example: "2024-10-23T07:39:48.245Z"
 *       401:
 *         description: Unauthorized - Token is missing or invalid
 *       403:
 *         description: Forbidden - Token expired or invalid
 */
router.get('/user-details', authenticateToken, async (req, res) => {
  const { email, username, phone, id, isEmailVerified } = req.user;
  console.log(email,id);
  let userid = id;
  let userdetails = await User.findOne({_id: userid});

  console.log(userdetails);
  // Send the user profile data
  return res.status(200).json({
    status: 'success',
    data: {
      user: {
        email:userdetails.email,
        username: userdetails.username,
        phone:userdetails.phone,
        id: userdetails._id,
        referralCode: userdetails.referralCode,
        referredBy: userdetails.referredBy,
        isEmailVerified:userdetails.isEmailVerified,
      },
    },
    timestamp: new Date().toISOString(),
  });
});
/**
 * @swagger
 * /users/update-user:
 *   post:
 *     summary: Update user profile details
 *     description: Update user's username and phone. Email and ID cannot be changed.
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
 *               username:
 *                 type: string
 *                 example: NewUsername
 *               phone:
 *                 type: string
 *                 example: 03824895759
 *             required:
 *               - username
 *               - phone
 *     responses:
 *       200:
 *         description: Successfully updated user profile
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
 *                   example: Profile updated successfully
 *                 data:
 *                   type: object
 *                   properties:
 *                     user:
 *                       type: object
 *                       properties:
 *                         username:
 *                           type: string
 *                           example: NewUsername
 *                         phone:
 *                           type: string
 *                           example: 03824895759
 *                         email:
 *                           type: string
 *                           example: user@example.com
 *                         id:
 *                           type: string
 *                           example: 6717a3cae9197edcae68b98a
 *                         updatedAt:
 *                           type: string
 *                           example: "2024-10-23T07:39:48.245Z"
 *                 timestamp:
 *                   type: string
 *                   example: "2024-10-23T07:39:48.245Z"
 *       400:
 *         description: Bad Request - User cannot change email or ID
 *       401:
 *         description: Unauthorized - Token is missing or invalid
 *       403:
 *         description: Forbidden - Token expired or invalid
 */
router.post('/update-user',authenticateToken, async(req,res) =>{
const {username,phone} = req.body;
const email = req.user.email;
if(req.body.email || req.body._id){
  return res.status(400).json({message:'User Cannot change Email and ID'});
}
const user = await User.findOne({email});
user.username = username || user.username;
user.phone = phone || user.phone;

await user.save();
return res.status(200).json({
  status: 'success',
  message: 'Profile updated successfully',
  data: {
    user: {
      username: user.username,
      phone: user.phone,
      email: user.email, // Return the unchanged email
      id: user._id, // Return the unchanged ID
      updatedAt: user.updatedAt
    }
  },
  timestamp: new Date().toISOString()
});

});
module.exports = router;
