  import 'dotenv/config';
  import express from 'express';
  import mysql from 'mysql2';
  import cors from 'cors';
  import bodyParser from 'body-parser';
  import bcrypt from 'bcryptjs';
  import nodemailer from 'nodemailer';

  const app = express();
  app.use(cors());
  app.use(bodyParser.json());

  // ✅ MySQL connection
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

  // ✅ Nodemailer transporter (Gmail SMTP)
  const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  // ✅ Helper: 6-digit code generator
  function generateCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  // ----------------------------------------------------
  // SIGN UP + EMAIL VERIFICATION + LOGIN + RESEND CODE
  // ----------------------------------------------------
  app.post('/signup', async (req, res) => {
    const { fullname, email, password } = req.body;
    if (!fullname || !email || !password)
      return res.status(400).json({ message: 'All fields required' });

    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
      if (err) return res.status(500).json({ message: 'DB error' });
      if (results.length > 0)
        return res.status(409).json({ message: 'Email already registered' });

      try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const code = generateCode();
        const expires = new Date(Date.now() + 1000 * 60 * 15);

        const sql =
          'INSERT INTO users (fullname, email, password, verified, verification_code, verification_expires) VALUES (?, ?, ?, 0, ?, ?)';
        db.query(sql, [fullname, email, hashedPassword, code, expires], async err2 => {
          if (err2) return res.status(500).json({ message: 'Error saving user' });

          const mail = {
            from: `"${process.env.APP_NAME || 'Snorensics'}" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Verify your Snorensics account',
            html: `<p>Hello ${fullname},</p><p>Your verification code is <b>${code}</b></p>`,
          };

          try {
            await transporter.sendMail(mail);
            res.json({ message: 'User registered. Verification code sent.', email });
          } catch (err) {
            console.error(err);
            res.status(500).json({ message: 'Email send failed' });
          }
        });
      } catch (err) {
        res.status(500).json({ message: 'Server error' });
      }
    });
  });

  app.post('/verify', (req, res) => {
    const { email, code } = req.body;
    db.query(
      'SELECT verification_code, verification_expires, verified FROM users WHERE email = ?',
      [email],
      (err, results) => {
        if (err) return res.status(500).json({ message: 'DB error' });
        if (results.length === 0) return res.status(404).json({ message: 'User not found' });

        const user = results[0];
        if (user.verified) return res.status(400).json({ message: 'Already verified' });

        if (new Date() > new Date(user.verification_expires))
          return res.status(400).json({ message: 'Code expired' });

        if (user.verification_code !== code)
          return res.status(400).json({ message: 'Invalid code' });

        db.query(
          'UPDATE users SET verified = 1, verification_code = NULL, verification_expires = NULL WHERE email = ?',
          [email],
          err2 => {
            if (err2) return res.status(500).json({ message: 'Update error' });
            res.json({ message: 'Email verified successfully!' });
          }
        );
      }
    );
  });

  app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
      if (err) return res.status(500).json({ message: 'DB error' });
      if (results.length === 0) return res.status(401).json({ message: 'Invalid credentials' });

      const user = results[0];
      if (!user.verified)
        return res.status(403).json({ message: 'Email not verified' });

      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.status(401).json({ message: 'Invalid credentials' });

      res.json({ message: `Welcome back, ${user.fullname}!` });
    });
  });

  app.post('/resend', (req, res) => {
    const { email } = req.body;
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
      if (err) return res.status(500).json({ message: 'DB error' });
      if (results.length === 0) return res.status(404).json({ message: 'User not found' });

      const user = results[0];
      if (user.verified) return res.status(400).json({ message: 'Already verified' });

      const newCode = generateCode();
      const expires = new Date(Date.now() + 1000 * 60 * 15);

      db.query(
        'UPDATE users SET verification_code = ?, verification_expires = ? WHERE email = ?',
        [newCode, expires, email],
        async err2 => {
          if (err2) return res.status(500).json({ message: 'Error updating code' });

          const mail = {
            from: `"Snorensics" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'New Verification Code',
            html: `<p>Your new verification code is <b>${newCode}</b></p>`,
          };
          try {
            await transporter.sendMail(mail);
            res.json({ message: 'New verification code sent.' });
          } catch {
            res.status(500).json({ message: 'Email failed to send' });
          }
        }
      );
    });
  });

  app.post('/forgot-password', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email required.' });

  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error.' });
    if (results.length === 0) return res.status(404).json({ message: 'Email not found.' });

    const user = results[0];
    const resetCode = generateCode();
    const expires = new Date(Date.now() + 15 * 60 * 1000);

    db.query('UPDATE users SET reset_code = ?, reset_expires = ? WHERE email = ?', [resetCode, expires, email], async err2 => {
      if (err2) return res.status(500).json({ message: 'Failed to save reset code.' });

      try {
        await transporter.sendMail({
          from: `"Snorensics" <${process.env.EMAIL_USER}>`,
          to: email,
          subject: 'Password Reset Code',
          html: `<p>Hello ${user.fullname},</p><p>Your reset code is: <b>${resetCode}</b></p><p>Expires in 15 minutes.</p>`,
        });
        res.json({ message: 'Reset code sent successfully!' });
      } catch (mailErr) {
        console.error(mailErr);
        res.status(500).json({ message: 'Failed to send email.' });
      }
    });
  });
});

// ---------------- VERIFY RESET CODE ----------------
app.post('/verify-reset-code', (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ message: 'Email and code required.' });

  db.query('SELECT reset_code, reset_expires FROM users WHERE email = ?', [email], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error.' });
    if (results.length === 0) return res.status(404).json({ message: 'User not found.' });

    const user = results[0];
    if (!user.reset_code || !user.reset_expires) return res.status(400).json({ message: 'No reset request found.' });
    if (new Date() > new Date(user.reset_expires)) return res.status(400).json({ message: 'Reset code expired.' });
    if (user.reset_code !== code) return res.status(400).json({ message: 'Invalid reset code.' });

    res.json({ message: 'Code verified successfully.' });
  });
});

// ---------------- RESET PASSWORD ----------------
app.post('/reset-password', async (req, res) => {
  const { email, code, newPassword } = req.body;
  if (!email || !code || !newPassword) return res.status(400).json({ message: 'All fields required.' });

  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error.' });
    if (results.length === 0) return res.status(404).json({ message: 'User not found.' });

    const user = results[0];
    if (!user.reset_code || !user.reset_expires) return res.status(400).json({ message: 'No reset request found.' });
    if (new Date() > new Date(user.reset_expires)) return res.status(400).json({ message: 'Reset code expired.' });
    if (user.reset_code !== code) return res.status(400).json({ message: 'Invalid reset code.' });

    try {
      const hashed = await bcrypt.hash(newPassword, 10);
      db.query('UPDATE users SET password = ?, reset_code = NULL, reset_expires = NULL WHERE email = ?', [hashed, email], err2 => {
        if (err2) return res.status(500).json({ message: 'Failed to update password.' });
        res.json({ message: 'Password reset successfully!' });
      });
    } catch (hashErr) {
      console.error(hashErr);
      res.status(500).json({ message: 'Server error during password hash.' });
    }
  });
});

  // ----------------------------------------------------
  const PORT = 3000;
  app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
