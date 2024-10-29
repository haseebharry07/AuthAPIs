const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: {type: String,required: function () { return !this.isGuest; } // Required only if not a guest
  },
  email: {type: String,required: function () { return !this.isGuest; } // Required only if not a guest
  },
  phone: {
    type: String,
    required: [false, 'Phone number is required'],
    default: null
  },
  otpCode: {
    type: String,
    required: [false, 'OTP code is required'],
    default: null
  },
  referralCode: {
    type: String,
    required: [false, 'Referral code is required'],
    default: null
  },
  password: {
    type: String,
    required: function () { return !this.isGuest; } // Required only if not a guest
  },
  referredBy: { type: String },
  otpExpiration: {
    type: Date,
    required: [false, 'OTP expiration is required'],
    default: null
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  isEmailVerified: { type: Boolean, default: false },
  isDeleted: { type: Boolean, default: false },
  isGuest: { type: Boolean, default: false },
  guestUserId: { type: String }, // Unique ID for guest users
  accessToken: { type: String }, // Access token for guest users
  tokenExpiration: { type: Date }, // Expiry date for access token
  emailUpdateOtp:{ type : String },
  pendingNewEmail:{ type: String }
});

// Customize the toJSON method to convert dates to ISO strings
userSchema.set('toJSON', {
  transform: (doc, ret) => {
    ret.createdAt = ret.createdAt.toISOString();
    ret.updatedAt = ret.updatedAt.toISOString();
    return ret;
  }
});

const User = mongoose.model('User', userSchema);

module.exports = User;
