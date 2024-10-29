
// File: jobs/removeExpiredGuests.js
const cron = require('node-cron');
const mongoose = require('mongoose');
const User = require('../models/users'); // Adjust the path based on your folder structure


// Schedule the cron job to run every day at midnight
cron.schedule('*/1 * * * *', async () => {
  console.log("Running cron job to remove expired guest users...");
  try {
    const now = new Date();
    const result = await User.deleteMany({
      isGuest: true,
      tokenExpiration: { $lt: now }
    });
    console.log(`Deleted ${result.deletedCount} expired guest users.`);
  } catch (error) {
    console.error("Error running cron job:", error);
  }
});
