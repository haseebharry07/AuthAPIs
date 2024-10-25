const mongoose = require('mongoose');
require('dotenv').config();
const DBConnection = process.env.MONGODB;

const connectDB = async () => {
    try {
      // Simply use mongoose.connect with the connection string only
      await mongoose.connect(DBConnection);
      console.log('MongoDB connected ON: ', DBConnection);
    } catch (error) {
      console.error('MongoDB connection error:', error);
      process.exit(1);
    }
  };
  
  module.exports = connectDB;