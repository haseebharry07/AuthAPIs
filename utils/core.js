function generateReferralCode() {
    return Math.random().toString(36).substr(2, 8).toUpperCase(); // Generates a random 8-character code
  }

  function generateOTP(length = 6) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let otp = '';
    for (let i = 0; i < length; i++) {
        otp += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return otp;
}
  module.exports = {generateReferralCode, generateOTP};
