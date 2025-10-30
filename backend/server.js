import 'dotenv/config'; // Must be the first line to load environment variables

import express from 'express';
import mysql from 'mysql2';
import cors from 'cors';
import bodyParser from 'body-parser';
import bcrypt from 'bcryptjs';
import nodemailer from 'nodemailer';

const app = express();
app.use(cors());
app.use(bodyParser.json());

// MySQL Connection: Using .env variables
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
});

db.connect(err => {
  if (err) throw err;
  console.log('✅ MySQL Connected...');
});

// Nodemailer SMTP setup: Using .env variables
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER, 
    pass: process.env.EMAIL_PASS, // This MUST be the 16-character Gmail App Password
  },
});

// Helper to generate 6-digit code
function generateCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// --- SIGNUP ROUTE ---
app.post('/signup', async (req, res) => {
  const { fullname, email, password } = req.body;
  if (!fullname || !email || !password) return res.status(400).json({ message: 'All fields required' });

  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ message: 'Database error checking existing user' }); }
    if (results.length > 0) return res.status(409).json({ message: 'Email already registered' });

    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const verificationCode = generateCode();
      const expiresAt = new Date(Date.now() + 1000 * 60 * 15); // 15 min expiry

      const sql = 'INSERT INTO users (fullname, email, password, verified, verification_code, verification_expires) VALUES (?, ?, ?, 0, ?, ?)';
      db.query(sql, [fullname, email, hashedPassword, verificationCode, expiresAt], async (err) => {
        if (err) { console.error(err); return res.status(500).json({ message: 'Error saving new user' }); }

        const mailOptions = {
          from: `"${process.env.APP_NAME || 'Snorensics'}" <${process.env.EMAIL_USER}>`,
          to: email,
          subject: 'Verify your Snorensics account',
          html: `<p>Hi ${fullname},</p><p>Your verification code is <strong>${verificationCode}</strong></p><p>This code expires in 15 minutes.</p>`,
        };

        try {
          await transporter.sendMail(mailOptions);
          return res.json({ message: 'User registered. Verification code sent.', email }); 
        } catch (mailErr) {
          console.error('❌ SendMail Error:', mailErr);
          // Log error but still proceed to verification step on client side
          return res.status(500).json({ message: 'Failed to send verification email. Please check your SMTP settings.' }); 
        }
      });
    } catch (hashErr) {
      console.error(hashErr);
      res.status(500).json({ message: 'Password processing error' });
    }
  });
});

// --- VERIFY EMAIL ROUTE ---
app.post('/verify', (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ message: 'Email and code required' });

  db.query('SELECT verification_code, verification_expires, verified FROM users WHERE email = ?', [email], (err, results) => {
    if (err) return res.status(500).json({ message: 'DB error' });
    if (results.length === 0) return res.status(404).json({ message: 'User not found' });

    const user = results[0];
    if (user.verified) return res.status(400).json({ message: 'Already verified' });

    const now = new Date();
    const expires = new Date(user.verification_expires);
    if (now > expires) return res.status(400).json({ message: 'Code expired' });
    if (user.verification_code !== code) return res.status(400).json({ message: 'Invalid code' });

    db.query('UPDATE users SET verified = 1, verification_code = NULL, verification_expires = NULL WHERE email = ?', [email], (err2) => {
      if (err2) return res.status(500).json({ message: 'DB error updating verification' });
      return res.json({ message: 'Email verified successfully!' });
    });
  });
});

// --- LOGIN ROUTE (FIXED) ---
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).json({ message: 'DB error' });
    // IMPORTANT: If user not found, return generic "Invalid credentials"
    if (results.length === 0) return res.status(401).json({ message: 'Invalid credentials' }); 

    const user = results[0];
    
    // Check for verification first
    if (!user.verified) {
        // Return 403 status for "Forbidden" access due to unverified email
        return res.status(403).json({ message: 'Email not verified' }); 
    }

    try {
      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.status(401).json({ message: 'Invalid credentials' });

      return res.json({ message: `Welcome back, ${user.fullname}!` });
    } catch (error) {
      console.error(error);
      return res.status(500).json({ message: 'Error verifying password' });
    }
  });
});

// --- START SERVER ---
const PORT = 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));