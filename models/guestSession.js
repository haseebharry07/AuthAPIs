const mongoose = require('mongoose');

const guestSessionSchema = new mongoose.Schema({
  guestID: { type: mongoose.Types.ObjectId, required: true, unique: true },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true },
});

module.exports = mongoose.model('GuestSession', guestSessionSchema);