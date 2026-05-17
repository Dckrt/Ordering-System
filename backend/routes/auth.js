// ============================================================
// backend/routes/auth.js — Updated with super_admin support
// ============================================================

const express  = require('express');
const router   = express.Router();
const oracledb = require('oracledb');
const { getConnection } = require('../db');

// ── POST /api/auth/login ─────────────────────────────────────
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ success: false, message: 'Email and password required' });

  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `SELECT user_id                        AS "user_id",
              full_name                      AS "full_name",
              email                          AS "email",
              phone                          AS "phone",
              role                           AS "role",
              NVL(status,'active')           AS "status",
              NVL(is_super_admin, 0)         AS "is_super_admin",
              profile_image                  AS "profile_image"
       FROM users
       WHERE LOWER(email) = LOWER(:email) AND password = :password`,
      { email, password },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    if (!result.rows.length)
      return res.status(401).json({ success: false, message: 'Invalid email or password.' });

    const user = result.rows[0];
    if (user.status === 'blocked')
      return res.status(403).json({ success: false, message: 'Your account has been blocked. Contact support.' });

    res.json({ success: true, user });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ success: false, message: err.message });
  } finally {
    if (conn) await conn.close();
  }
});


// ── POST /api/auth/register ──────────────────────────────────
router.post('/register', async (req, res) => {
  const { full_name, email, phone, password, role, skip_otp_check } = req.body;

  if (!full_name || !email || !password)
    return res.status(400).json({ success: false, message: 'Name, email, and password required' });

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ success: false, message: 'Invalid email format' });

  if (password.length < 6)
    return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });

  let conn;
  try {
    conn = await getConnection();

    // Check OTP verified (unless skipped by admin adding user)
    if (!skip_otp_check) {
      const otpCheck = await conn.execute(
        `SELECT id FROM (
           SELECT id FROM otp_tokens
           WHERE LOWER(email) = LOWER(:email)
             AND used = 1
             AND expires_at > SYSDATE - 10/1440
           ORDER BY created_at DESC
         ) WHERE ROWNUM = 1`,
        { email },
        { outFormat: oracledb.OUT_FORMAT_OBJECT }
      );
      if (!otpCheck.rows.length) {
        return res.status(403).json({
          success: false,
          message: 'Please verify your email with OTP before registering.',
        });
      }
    }

    // Check if email already registered
    const check = await conn.execute(
      `SELECT user_id FROM users WHERE LOWER(email) = LOWER(:email)`,
      { email }, { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    if (check.rows.length > 0)
      return res.status(409).json({ success: false, message: 'Email already registered. Please sign in.' });

    // Insert new user
    const userRole = role || 'customer';
    const insert = await conn.execute(
      `INSERT INTO users (full_name, email, phone, password, role, status, is_super_admin)
       VALUES (:full_name, :email, :phone, :password, :role, 'active', 0)
       RETURNING user_id INTO :user_id`,
      {
        full_name, email,
        phone:   phone || null,
        password,
        role:    userRole,
        user_id: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER }
      }
    );
    await conn.commit();
    const userId = insert.outBinds.user_id[0];
    console.log(`✅ New user registered: ${email} (ID: ${userId})`);

    res.json({
      success: true,
      user: { user_id: userId, full_name, email, phone: phone || null, role: userRole, status: 'active', is_super_admin: 0, profile_image: null }
    });
  } catch (err) {
    console.error('Register error:', err.message);
    res.status(500).json({ success: false, message: err.message });
  } finally {
    if (conn) await conn.close();
  }
});


// ── POST /api/auth/google ─────────────────────────────────────
router.post('/google', async (req, res) => {
  const { email, full_name } = req.body;
  if (!email) return res.status(400).json({ success: false, message: 'Email required' });

  let conn;
  try {
    conn = await getConnection();
    const check = await conn.execute(
      `SELECT user_id       AS "user_id",
              full_name     AS "full_name",
              email         AS "email",
              phone         AS "phone",
              role          AS "role",
              NVL(status,'active')     AS "status",
              NVL(is_super_admin,0)    AS "is_super_admin",
              profile_image            AS "profile_image"
       FROM users WHERE LOWER(email) = LOWER(:email)`,
      { email }, { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    if (check.rows.length > 0) {
      const user = check.rows[0];
      if (user.status === 'blocked')
        return res.status(403).json({ success: false, message: 'Your account has been blocked.' });
      return res.json({ success: true, user });
    }
    const insert = await conn.execute(
      `INSERT INTO users (full_name, email, phone, password, role, status, is_super_admin)
       VALUES (:full_name, :email, NULL, :password, 'customer', 'active', 0)
       RETURNING user_id INTO :user_id`,
      { full_name: full_name || email.split('@')[0], email, password: 'google_'+Date.now(), user_id: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER } }
    );
    await conn.commit();
    const userId = insert.outBinds.user_id[0];
    res.json({ success: true, user: { user_id: userId, full_name: full_name||email, email, phone: null, role: 'customer', status: 'active', is_super_admin: 0, profile_image: null } });
  } catch (err) {
    console.error('Google auth error:', err.message);
    res.status(500).json({ success: false, message: err.message });
  } finally {
    if (conn) await conn.close();
  }
});


// ── PUT /api/auth/profile/:userId ────────────────────────────
router.put('/profile/:userId', async (req, res) => {
  const { full_name, phone, password, profile_image } = req.body;
  let conn;
  try {
    conn = await getConnection();
    let sql, binds;
    if (password && profile_image) {
      sql   = `UPDATE users SET full_name=:full_name, phone=:phone, password=:password, profile_image=:profile_image WHERE user_id=:id`;
      binds = { full_name, phone: phone||null, password, profile_image, id: parseInt(req.params.userId) };
    } else if (password) {
      sql   = `UPDATE users SET full_name=:full_name, phone=:phone, password=:password WHERE user_id=:id`;
      binds = { full_name, phone: phone||null, password, id: parseInt(req.params.userId) };
    } else if (profile_image) {
      sql   = `UPDATE users SET full_name=:full_name, phone=:phone, profile_image=:profile_image WHERE user_id=:id`;
      binds = { full_name, phone: phone||null, profile_image, id: parseInt(req.params.userId) };
    } else {
      sql   = `UPDATE users SET full_name=:full_name, phone=:phone WHERE user_id=:id`;
      binds = { full_name, phone: phone||null, id: parseInt(req.params.userId) };
    }
    await conn.execute(sql, binds);
    await conn.commit();
    res.json({ success: true });
  } catch (err) {
    console.error('Profile update error:', err.message);
    res.status(500).json({ success: false, message: err.message });
  } finally {
    if (conn) await conn.close();
  }
});

module.exports = router;