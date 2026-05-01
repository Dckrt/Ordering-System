// ============================================================
// backend/server.js — FIXED
// ============================================================

// ✅ STEP 1: dotenv MUST be the very first line
// __dirname = backend/
// '../.env' = one level up = OrderingSystemm/.env
require('dotenv').config({ path: require('path').join(__dirname, '../.env') });

const express = require('express');
const cors    = require('cors');
const path    = require('path');

const app = express();

app.use(cors());
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));

// Serve frontend static files
app.use(express.static(path.join(__dirname, '..')));

// Health check
app.get('/api/test', (req, res) => {
  res.json({ message: 'Server is running!', time: new Date().toISOString() });
});

// Routes
app.use('/api/auth',     require('./routes/auth'));
app.use('/api/products', require('./routes/products'));
app.use('/api/orders',   require('./routes/orders'));
app.use('/api/admin',    require('./routes/admin'));
app.use('/api/otp',      require('./routes/otp'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log(`📧 Gmail user: ${process.env.GMAIL_USER || '⚠️  GMAIL_USER not set in .env'}`);
  console.log(`🔑 Gmail pass: ${process.env.GMAIL_PASS ? '✅ Set' : '⚠️  GMAIL_PASS not set in .env'}`);
});