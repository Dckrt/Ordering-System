// ============================================================
// backend/routes/admin.js — Fixed delete with cascade
// Fix: ORA-02292 — delete child records first before user
// ============================================================

const express  = require('express');
const router   = express.Router();
const oracledb = require('oracledb');
const { getConnection } = require('../db');

// ── Helper: detect user columns ──────────────────────────────
async function getUserColumns(conn) {
  const result = await conn.execute(
    `SELECT LOWER(column_name) AS "col"
     FROM user_tab_columns
     WHERE UPPER(table_name) = 'USERS'`,
    {}, { outFormat: oracledb.OUT_FORMAT_OBJECT }
  );
  return result.rows.map(r => r.col);
}

// ── GET /api/admin/dashboard ──────────────────────────────────
router.get('/dashboard', async (req, res) => {
  let conn;
  try {
    conn = await getConnection();
    const [orders, customers, products] = await Promise.all([
      conn.execute(`SELECT COUNT(*) AS "total", NVL(SUM(total),0) AS "revenue" FROM orders`, {}, { outFormat: oracledb.OUT_FORMAT_OBJECT }),
      conn.execute(`SELECT COUNT(*) AS "total" FROM users WHERE LOWER(NVL(role,'customer')) != 'admin'`, {}, { outFormat: oracledb.OUT_FORMAT_OBJECT }),
      conn.execute(`SELECT COUNT(*) AS "total" FROM products`, {}, { outFormat: oracledb.OUT_FORMAT_OBJECT }),
    ]);
    res.json({
      total_orders:    orders.rows[0].total    || 0,
      total_revenue:   orders.rows[0].revenue  || 0,
      total_customers: customers.rows[0].total || 0,
      total_products:  products.rows[0].total  || 0,
    });
  } catch (err) {
    console.error('Dashboard error:', err.message);
    res.status(500).json({ error: err.message });
  } finally { if (conn) await conn.close(); }
});


// ── GET /api/admin/customers ──────────────────────────────────
router.get('/customers', async (req, res) => {
  let conn;
  try {
    conn = await getConnection();
    const cols        = await getUserColumns(conn);
    const statusCol   = cols.includes('status')         ? `NVL(status,'active')`                           : `'active'`;
    const createdCol  = cols.includes('created_at')     ? `TO_CHAR(created_at,'YYYY-MM-DD"T"HH24:MI:SS')` : `TO_CHAR(SYSDATE,'YYYY-MM-DD"T"HH24:MI:SS')`;
    const superAdmCol = cols.includes('is_super_admin') ? `NVL(is_super_admin,0)`                         : `0`;

    const result = await conn.execute(
      `SELECT user_id              AS "user_id",
              full_name            AS "full_name",
              email                AS "email",
              phone                AS "phone",
              NVL(role,'customer') AS "role",
              ${statusCol}         AS "status",
              ${createdCol}        AS "created_at",
              ${superAdmCol}       AS "is_super_admin"
       FROM users
       WHERE LOWER(NVL(role,'customer')) != 'admin'
       ORDER BY user_id DESC`,
      {}, { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    res.json(result.rows);
  } catch (err) {
    console.error('getCustomers error:', err.message);
    res.json([]);
  } finally { if (conn) await conn.close(); }
});


// ── GET /api/admin/all-users ──────────────────────────────────
router.get('/all-users', async (req, res) => {
  let conn;
  try {
    conn = await getConnection();
    const cols        = await getUserColumns(conn);
    const statusCol   = cols.includes('status')         ? `NVL(status,'active')`                           : `'active'`;
    const createdCol  = cols.includes('created_at')     ? `TO_CHAR(created_at,'YYYY-MM-DD"T"HH24:MI:SS')` : `TO_CHAR(SYSDATE,'YYYY-MM-DD"T"HH24:MI:SS')`;
    const superAdmCol = cols.includes('is_super_admin') ? `NVL(is_super_admin,0)`                         : `0`;

    const result = await conn.execute(
      `SELECT user_id              AS "user_id",
              full_name            AS "full_name",
              email                AS "email",
              phone                AS "phone",
              NVL(role,'customer') AS "role",
              ${statusCol}         AS "status",
              ${createdCol}        AS "created_at",
              ${superAdmCol}       AS "is_super_admin"
       FROM users
       ORDER BY user_id DESC`,
      {}, { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    res.json(result.rows);
  } catch (err) {
    console.error('getAllUsers error:', err.message);
    res.json([]);
  } finally { if (conn) await conn.close(); }
});


// ── PUT /api/admin/customers/:id/status ──────────────────────
router.put('/customers/:id/status', async (req, res) => {
  const { status } = req.body;
  if (!['active', 'blocked'].includes(status))
    return res.status(400).json({ success: false, message: 'Invalid status' });

  let conn;
  try {
    conn = await getConnection();
    try {
      await conn.execute(`ALTER TABLE users ADD (status VARCHAR2(20) DEFAULT 'active')`);
      await conn.commit();
    } catch (e) { /* already exists */ }
    await conn.execute(
      `UPDATE users SET status = :status WHERE user_id = :id`,
      { status, id: parseInt(req.params.id) }
    );
    await conn.commit();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally { if (conn) await conn.close(); }
});


// ── DELETE /api/admin/customers/:id ──────────────────────────
// Deletes user + all related records in correct order
// to avoid ORA-02292 integrity constraint errors
router.delete('/customers/:id', async (req, res) => {
  const targetId    = parseInt(req.params.id);
  const requesterId = parseInt(req.body.requester_id || 0);

  let conn;
  try {
    conn = await getConnection();
    const cols        = await getUserColumns(conn);
    const superAdmCol = cols.includes('is_super_admin') ? `NVL(is_super_admin,0)` : `0`;

    // ── Get target user info ──────────────────────────────
    const targetRes = await conn.execute(
      `SELECT role          AS "role",
              email         AS "email",
              ${superAdmCol} AS "is_super_admin"
       FROM users WHERE user_id = :id`,
      { id: targetId },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );

    if (!targetRes.rows.length)
      return res.status(404).json({ success: false, message: 'User not found.' });

    const target = targetRes.rows[0];

    // ── Permission checks ─────────────────────────────────
    if (targetId === requesterId)
      return res.status(403).json({ success: false, message: 'You cannot delete your own account.' });

    if (target.is_super_admin === 1)
      return res.status(403).json({ success: false, message: 'Cannot delete the Super Admin account.' });

    // Get requester info
    const reqRes = await conn.execute(
      `SELECT role AS "role", ${superAdmCol} AS "is_super_admin"
       FROM users WHERE user_id = :id`,
      { id: requesterId },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );

    if (!reqRes.rows.length)
      return res.status(403).json({ success: false, message: 'Requester not found.' });

    const requester = reqRes.rows[0];

    // Only super_admin can delete other admins
    if ((target.role || '').toLowerCase() === 'admin' && requester.is_super_admin !== 1)
      return res.status(403).json({ success: false, message: 'Only the Super Admin can delete other admins.' });

    // ── CASCADE DELETE — correct order to avoid FK errors ──
    // Step 1: Get all order IDs for this user
    const orderRes = await conn.execute(
      `SELECT order_id FROM orders WHERE user_id = :id`,
      { id: targetId },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    const orderIds = orderRes.rows.map(r => r.order_id || r.ORDER_ID);

    // Step 2: Delete order_items for each order
    if (orderIds.length > 0) {
      for (const orderId of orderIds) {
        try {
          await conn.execute(
            `DELETE FROM order_items WHERE order_id = :oid`,
            { oid: orderId }
          );
        } catch (e) {
          console.warn('Skip order_items delete:', e.message);
        }
      }
    }

    // Step 3: Delete notifications for this user
    try {
      await conn.execute(
        `DELETE FROM notifications WHERE user_id = :id`,
        { id: targetId }
      );
    } catch (e) {
      console.warn('Skip notifications delete (table may not exist):', e.message);
    }

    // Step 4: Delete notifications related to this user's orders
    if (orderIds.length > 0) {
      for (const orderId of orderIds) {
        try {
          await conn.execute(
            `DELETE FROM notifications WHERE order_id = :oid`,
            { oid: orderId }
          );
        } catch (e) { /* ignore */ }
      }
    }

    // Step 5: Delete the user's orders
    try {
      await conn.execute(
        `DELETE FROM orders WHERE user_id = :id`,
        { id: targetId }
      );
    } catch (e) {
      console.warn('Skip orders delete:', e.message);
    }

    // Step 6: Delete OTP tokens for this user's email
    try {
      await conn.execute(
        `DELETE FROM otp_tokens
         WHERE LOWER(email) = (SELECT LOWER(email) FROM users WHERE user_id = :id)`,
        { id: targetId }
      );
    } catch (e) {
      console.warn('Skip otp_tokens delete:', e.message);
    }

    // Step 7: Finally delete the user
    await conn.execute(
      `DELETE FROM users WHERE user_id = :id`,
      { id: targetId }
    );

    await conn.commit();
    console.log(`✅ User ${targetId} (${target.email}) deleted by requester ${requesterId}`);
    res.json({ success: true, message: 'User deleted successfully.' });

  } catch (err) {
    try { await conn.rollback(); } catch (e) {}
    console.error('❌ Delete user error:', err.message);
    res.status(500).json({ success: false, message: err.message });
  } finally { if (conn) await conn.close(); }
});


// ── GET /api/admin/categories ─────────────────────────────────
router.get('/categories', async (req, res) => {
  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `SELECT category_id AS "category_id", name AS "name", description AS "description"
       FROM categories ORDER BY category_id`,
      {}, { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
  finally { if (conn) await conn.close(); }
});

router.post('/categories', async (req, res) => {
  const { name, description } = req.body;
  if (!name) return res.status(400).json({ success: false, message: 'Name required' });
  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `INSERT INTO categories (name, description) VALUES (:name, :description) RETURNING category_id INTO :category_id`,
      { name, description: description || null, category_id: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER } }
    );
    await conn.commit();
    res.json({ success: true, category_id: result.outBinds.category_id[0] });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  finally { if (conn) await conn.close(); }
});

router.put('/categories/:id', async (req, res) => {
  const { name, description } = req.body;
  let conn;
  try {
    conn = await getConnection();
    await conn.execute(
      `UPDATE categories SET name=:name, description=:description WHERE category_id=:id`,
      { name, description: description || null, id: parseInt(req.params.id) }
    );
    await conn.commit();
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  finally { if (conn) await conn.close(); }
});

router.delete('/categories/:id', async (req, res) => {
  let conn;
  try {
    conn = await getConnection();
    await conn.execute(`DELETE FROM categories WHERE category_id=:id`, { id: parseInt(req.params.id) });
    await conn.commit();
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  finally { if (conn) await conn.close(); }
});


// ── GET /api/admin/reports ────────────────────────────────────
router.get('/reports', async (req, res) => {
  let conn;
  try {
    conn = await getConnection();
    let rows = [];
    try {
      const tc = await conn.execute(
        `SELECT COUNT(*) AS "cnt" FROM user_tables WHERE UPPER(table_name) = 'ORDER_ITEMS'`,
        {}, { outFormat: oracledb.OUT_FORMAT_OBJECT }
      );
      if (tc.rows[0].cnt > 0) {
        const cc = await conn.execute(`SELECT COUNT(*) AS "cnt" FROM order_items`, {}, { outFormat: oracledb.OUT_FORMAT_OBJECT });
        if (cc.rows[0].cnt > 0) {
          try {
            const r = await conn.execute(
              `SELECT oi.name                         AS "product_name",
                      SUM(oi.quantity)                AS "total_sold",
                      SUM(oi.price * oi.quantity)     AS "total_revenue"
               FROM order_items oi
               JOIN orders o ON oi.order_id = o.order_id
               WHERE o.status != 'Cancelled'
               GROUP BY oi.name
               ORDER BY SUM(oi.quantity) DESC`,
              {}, { outFormat: oracledb.OUT_FORMAT_OBJECT }
            );
            rows = r.rows;
          } catch (e) {
            const r = await conn.execute(
              `SELECT name AS "product_name", SUM(quantity) AS "total_sold", SUM(price*quantity) AS "total_revenue"
               FROM order_items GROUP BY name ORDER BY SUM(quantity) DESC`,
              {}, { outFormat: oracledb.OUT_FORMAT_OBJECT }
            );
            rows = r.rows;
          }
        }
      }
    } catch (e) {}

    if (!rows.length) {
      const r = await conn.execute(
        `SELECT name AS "product_name", 0 AS "total_sold", 0 AS "total_revenue"
         FROM products ORDER BY product_id`,
        {}, { outFormat: oracledb.OUT_FORMAT_OBJECT }
      );
      rows = r.rows;
    }
    res.json(Array.isArray(rows) ? rows : []);
  } catch (err) {
    console.error('Reports error:', err.message);
    res.json([]);
  } finally { if (conn) await conn.close(); }
});

module.exports = router;