const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true },
  phone: { type: String, required: true },
  otpCode: { type: String, required: true },
  referralCode: { type: String, required: true },
  password: { type: String, required: true },
  referredBy: { type: String, required: false },
  otpExpiration : { type: Date, required: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  isEmailVerified: { type: Boolean, default: false },
  isDeleted: { type: Boolean, default: false }
});
// Customize the toJSON method
userSchema.set('toJSON', {
    transform: (doc, ret) => {
      // Convert createdAt and updatedAt to ISO strings
      ret.createdAt = ret.createdAt.toISOString();
      ret.updatedAt = ret.updatedAt.toISOString();
      return ret;
    }
  });
const User = mongoose.model('User', userSchema);

module.exports = User;