const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true },
  phone: { type: String, required: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  isEmailVerified: { type: Boolean, default: false },
  isDeleted: { type: Boolean, default: false },
  guestID:{ type: String, required: false }
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
const GuestUser = mongoose.model('GuestUser', userSchema);

module.exports = GuestUser;