var createError = require('http-errors');
var express = require('express');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

var app = express();
const cors = require('cors');

const session = require('express-session');
const passport = require('passport');
var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');


//Start Custom Code Here
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 3500;
const connectDB = require('./db');
require('dotenv').config();
//ToConnectDB
connectDB();

//For MiddleWare
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use('/api', indexRouter);
app.use('/users', usersRouter);
// Express session middleware
app.use(session({
  secret: JWT_SECRET, 
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours in milliseconds
}));
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Testing APIs',
      version: '1.0.0',
      description: 'All APIs for Testing',
    },
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
    security: [
      {
        bearerAuth: [], // Applies this scheme to all routes by default
      },
    ],
  },
  apis: ['./routes/*.js'], // Points to the API route files
};
require('./jobs/removeExpiredGuests');
// Initialize swagger-jsdoc
const swaggerDocs = swaggerJsdoc(swaggerOptions);
console.log(swaggerDocs);
// Serve Swagger UI
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));
app.use((req, res, next) => {
  console.log(req.url);  // Log every request's URL
  next();
});
// Initialize passport and use session
app.use(passport.initialize());
app.use(passport.session());


//End

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));



// catch 404 and forward to error handler
app.use(function(err,req, res, next) {
  console.error(err.stack);
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});


app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log('Swagger docs available at http://localhost:3500/api-docs');
});


module.exports = app;
