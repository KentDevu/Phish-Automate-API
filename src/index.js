require('dotenv').config();

const express = require('express');
const emailRoutes = require('./routes/emails');
const { createTable } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.raw({ type: 'application/json', limit: '10mb' })); // Allow large payloads for emails

// Initialize database
createTable();

// Routes
app.use('/api/emails', emailRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;