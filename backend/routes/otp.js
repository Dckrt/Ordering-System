// ============================================================
// backend/routes/otp.js — FIXED VERSION
// ============================================================

require('dotenv').config({ path: require('path').join(__dirname, '../../.env') });

const express    = require('express');
const router     = express.Router();
const oracledb   = require('oracledb');
const nodemailer = require('nodemailer');
const { getConnection } = require('../db');

// ── Create transporter fresh every time (ensures .env is loaded) ──
function getTransporter() {
  console.log('📧 Creating transporter with:', process.env.GMAIL_USER);
  return nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_PASS,
    },
  });
}

// ── Generate 6-digit OTP ─────────────────────────────────────
function generateOTP() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// ============================================================
// POST /api/otp/send
// ============================================================
router.post('/send', async (req, res) => {
  const { email } = req.body;
  console.log('📨 Send OTP request for:', email);

  if (!email || !email.includes('@')) {
    return res.status(400).json({ success: false, message: 'Please provide a valid email address.' });
  }

  if (!process.env.GMAIL_USER || !process.env.GMAIL_PASS) {
    console.error('❌ Gmail not configured. GMAIL_USER:', process.env.GMAIL_USER);
    return res.status(500).json({ success: false, message: 'Email service not configured.' });
  }

  const otp        = generateOTP();
  const expiryMins = parseInt(process.env.OTP_EXPIRES_MINUTES) || 5;

  let conn;
  try {
    conn = await getConnection();

    // Delete old OTPs for this email
    await conn.execute(
      `DELETE FROM otp_tokens WHERE LOWER(email) = LOWER(:email)`,
      { email }
    );

    // Insert new OTP using sequence
    await conn.execute(
      `INSERT INTO otp_tokens (id, email, otp_code, expires_at, used)
       VALUES (otp_tokens_seq.NEXTVAL, :email, :otp_code, SYSDATE + :mins/1440, 0)`,
      { email, otp_code: otp, mins: expiryMins }
    );
    await conn.commit();
    console.log(`✅ OTP saved to DB: ${otp} for ${email}`);

    // Send email
    const transporter = getTransporter();
    await transporter.sendMail({
      from:    `"Batangas Premium Naga" <${process.env.GMAIL_USER}>`,
      to:      email,
      subject: '🔐 Your OTP Verification Code — Batangas Premium Naga',
      text:    `Your OTP is: ${otp}\n\nExpires in ${expiryMins} minutes.\nDo not share this with anyone.`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#fff;border-radius:12px;border:1px solid #e5e7eb;">
          <div style="text-align:center;margin-bottom:24px;">
            <div style="display:inline-block;background:linear-gradient(135deg,#dc2626,#f97316);padding:12px 24px;border-radius:10px;">
              <span style="color:white;font-size:18px;font-weight:bold;">🍖 Batangas Premium Naga</span>
            </div>
          </div>
          <h2 style="color:#111;margin-bottom:8px;text-align:center;">Email Verification</h2>
          <p style="color:#6b7280;text-align:center;margin-bottom:28px;">Use the code below to verify your email address.</p>
          <div style="background:#fff7f7;border:2px dashed #dc2626;border-radius:12px;padding:28px;text-align:center;margin-bottom:24px;">
            <p style="font-size:12px;color:#9ca3af;margin:0 0 8px;text-transform:uppercase;letter-spacing:.1em;">YOUR OTP CODE</p>
            <p style="font-size:44px;font-weight:900;letter-spacing:14px;color:#dc2626;margin:0;">${otp}</p>
          </div>
          <p style="color:#6b7280;font-size:13px;text-align:center;margin:0;">⏱️ This code expires in <strong>${expiryMins} minutes</strong></p>
          <p style="color:#6b7280;font-size:13px;text-align:center;margin:6px 0 0;">🔒 Do not share this code with anyone.</p>
          <hr style="border:none;border-top:1px solid #f3f4f6;margin:24px 0;">
          <p style="color:#d1d5db;font-size:11px;text-align:center;margin:0;">Noona's Food Station · Naga City, Camarines Sur</p>
        </div>
      `,
    });

    console.log(`✅ OTP email sent to ${email}`);
    res.json({ success: true, message: `OTP sent to ${email}. Expires in ${expiryMins} minutes.` });

  } catch (err) {
    console.error('❌ Send OTP error:', err.message);
    console.error('Full error:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to send OTP. See server console for details.',
      debug:   err.message,
    });
  } finally {
    if (conn) await conn.close();
  }
});


// ============================================================
// POST /api/otp/verify
// ============================================================
router.post('/verify', async (req, res) => {
  const { email, otp } = req.body;
  console.log('🔍 Verify OTP request — email:', email, '| otp:', otp);

  if (!email || !otp) {
    return res.status(400).json({ success: false, message: 'Email and OTP are required.' });
  }

  // Clean the OTP — remove spaces and non-digits
  const cleanOTP = String(otp).replace(/\D/g, '').trim();
  console.log('🔢 Cleaned OTP:', cleanOTP);

  if (cleanOTP.length !== 6) {
    return res.status(400).json({ success: false, message: 'OTP must be a 6-digit number.' });
  }

  let conn;
  try {
    conn = await getConnection();

    // Get the latest OTP for this email
    const result = await conn.execute(
      `SELECT id           AS "id",
              otp_code     AS "otp_code",
              expires_at   AS "expires_at",
              used         AS "used"
       FROM otp_tokens
       WHERE LOWER(email) = LOWER(:email)
       ORDER BY created_at DESC
       FETCH FIRST 1 ROWS ONLY`,
      { email },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );

    console.log('📋 DB result rows:', result.rows.length);

    // No OTP found
    if (!result.rows.length) {
      console.log('❌ No OTP found for email:', email);
      return res.status(404).json({
        success: false,
        message: 'No OTP found for this email. Please request a new one.',
      });
    }

    const record = result.rows[0];
    console.log('📋 Found OTP record:', {
      id:         record.id,
      otp_code:   record.otp_code,
      used:       record.used,
      expires_at: record.expires_at,
    });

    // Already used
    if (record.used === 1) {
      return res.status(400).json({
        success: false,
        message: 'This OTP has already been used. Please request a new one.',
      });
    }

    // Check expiry
    const now = new Date();
    const exp = new Date(record.expires_at);
    console.log('⏰ Now:', now, '| Expires:', exp, '| Expired?', now > exp);

    if (now > exp) {
      return res.status(400).json({
        success: false,
        message: 'OTP has expired. Please request a new one.',
      });
    }

    // Check OTP code
    const storedOTP = String(record.otp_code).trim();
    console.log('🔢 Comparing — stored:', storedOTP, '| entered:', cleanOTP, '| match:', storedOTP === cleanOTP);

    if (storedOTP !== cleanOTP) {
      return res.status(400).json({
        success: false,
        message: 'Incorrect OTP. Please check your email and try again.',
      });
    }

    // ✅ SUCCESS — mark as used
    await conn.execute(
      `UPDATE otp_tokens SET used = 1 WHERE id = :id`,
      { id: record.id }
    );
    await conn.commit();
    console.log('✅ OTP verified successfully for:', email);

    res.json({ success: true, message: 'Email verified successfully! ✅' });

  } catch (err) {
    console.error('❌ Verify OTP error:', err.message);
    console.error('Full error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again.',
      debug:   err.message,
    });
  } finally {
    if (conn) await conn.close();
  }
});

module.exports = router;