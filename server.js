require('dotenv').config(); // Load env vars

console.log('DB_USER:', process.env.DB_USER);
console.log('DB_PASSWORD:', process.env.DB_PASSWORD ? '[SET]' : '[NOT SET]');

const express = require('express');
const cors = require('cors'); // ✅ Import CORS
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer'); // Added for email

// --- Import Google OAuth packages ---
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');

const app = express();

// ✅ Enable CORS
app.use(cors({
  origin: 'http://localhost:3000', // Change this to your frontend URL/port if needed (e.g., http://localhost:5173 for Vite)
  credentials: true
}));

app.use(express.json()); // Parse JSON in request body

// --- Setup express-session (needed for Passport) ---
app.use(session({
  secret: process.env.SESSION_SECRET || 'some-strong-secret',
  resave: false,
  saveUninitialized: false
}));

// --- Initialize passport and session ---
app.use(passport.initialize());
app.use(passport.session());

// MySQL Connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306
});

db.connect(err => {
  if (err) {
    console.error('Database connection failed:', err);
    return;
  }
  console.log('Connected to MySQL database');
});

// JWT secret key
const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key';

// Nodemailer setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,     // Your Gmail address
    pass: process.env.EMAIL_PASS      // App password
  }
});

// ----------------------
// Passport Google Strategy setup
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/api/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    // Implement findOrCreate logic here:
    // Assumes you have a `google_id` column in your users table (VARCHAR)

    db.query(
      'SELECT * FROM users WHERE google_id = ?',
      [profile.id],
      (err, results) => {
        if (err) return done(err);

        if (results.length > 0) {
          return done(null, results[0]);
        } else {
          // Insert new user with google_id, username from profile.displayName, and email
          db.query(
            'INSERT INTO users (username, email, google_id) VALUES (?, ?, ?)',
            [profile.displayName || '', profile.emails[0].value, profile.id],
            (insertErr, insertResult) => {
              if (insertErr) return done(insertErr);

              db.query(
                'SELECT * FROM users WHERE id = ?',
                [insertResult.insertId],
                (err2, newResults) => {
                  if (err2) return done(err2);
                  return done(null, newResults[0]);
                }
              );
            }
          );
        }
      }
    );
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  db.query('SELECT * FROM users WHERE id = ?', [id], (err, results) => {
    if (err) return done(err, null);
    done(null, results[0]);
  });
});

// ----------------------
// OAuth routes:
app.get('/api/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/api/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login', session: true }),
  (req, res) => {
    // Successful authentication, redirect or respond as needed
    res.redirect('http://localhost:3000/'); // Or send token/user info JSON for SPA apps if preferred
  }
);

// ------------------ API Routes ------------------ //

// 🧾 Sign Up (Registration)
app.post('/api/signup', async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({ error: 'Username, password, and email are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    db.query(
      'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
      [username, hashedPassword, email],
      (err) => {
        if (err) {
          if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'Username already exists' });
          }
          return res.status(500).json({ error: 'Database error' });
        }

        // Send welcome email
        const mailOptions = {
          from: process.env.EMAIL_USER,
          to: email,
          subject: 'Welcome to Our App!',
          text: `Hello ${username},\n\nThank you for registering. We're glad to have you!`
        };

        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            console.error('Failed to send welcome email:', error);
          } else {
            console.log('Email sent: ' + info.response);
          }
        });

        res.status(201).json({ message: 'User registered and welcome email sent' });
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Server error during sign up' });
  }
});

// 🔐 Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  db.query(
    'SELECT * FROM users WHERE username = ? OR email = ?',
    [username, username], // Pass both for lookup by username or email
    async (err, results) => {
      if (err || results.length === 0) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const user = results[0];
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });

      res.json({ message: 'Login successful', token });
    }
  );
});

// 🚪 Logout
app.post('/api/logout', (req, res) => {
  res.json({ message: 'Logout successful. Please delete the token on client side.' });
});

// 🔒 Protected Profile Route
app.get('/api/profile', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Token required' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });

    res.json({ message: 'Access granted', user: decoded });
  });
});

// 📧 Test Email Route (Optional)
app.post('/api/send-email', (req, res) => {
  const { to, subject, text } = req.body;

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to,
    subject,
    text
  };

  transporter.sendMail(mailOptions, (err, info) => {
    if (err) {
      console.error('Email send failed:', err);
      return res.status(500).json({ error: 'Email failed to send' });
    }
    res.json({ message: 'Email sent!', info });
  });
});

// ------------------ Server Start ------------------ //
const PORT = process.env.APP_PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
