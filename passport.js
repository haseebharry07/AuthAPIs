const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const { ExtractJwt } = require('passport-jwt');
const mongoose = require('mongoose');
const LocalStrategy = require('passport-local').Strategy;
const User = mongoose.model('User'); // Assuming User model is defined
const bcrypt = require('bcrypt'); // Make sure bcrypt is installed as well

const opts = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: process.env.JWT_SECRET, // Store the secret in your .env file
};

// JWT strategy to verify token
passport.use(new JwtStrategy(opts, async (jwt_payload, done) => {
  try {
    const user = await User.findById(jwt_payload.id);
    if (user) {
      return done(null, user);
    }
    return done(null, false);
  } catch (error) {
    console.error(error);
    return done(error, false);
  }
}));

// Local strategy for login
passport.use(new LocalStrategy(
    { usernameField: 'email' }, // Use email as the username field
    async (email, password, done) => {
      try {
        const user = await User.findOne({ email });
        if (!user) {
          return done(null, false, { message: 'Incorrect email.' });
        }
  
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          return done(null, false, { message: 'Incorrect password.' });
        }
  
        return done(null, user); // User authenticated successfully
      } catch (error) {
        return done(error);
      }
    }
  ));
  

// Serialize and deserialize user
passport.serializeUser((user, done) => {
    done(null, user.id); // Store the user ID in the session
  });
  
  passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id); // Retrieve user from the database
      done(null, user);
    } catch (error) {
      done(error);
    }
  });




module.exports = passport;
