require('dotenv').config();

const express = require('express');
const cors = require('cors');
const emailRoutes = require('./routes/emails');
const { createTable } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: true, // Allow all origins
  credentials: true, // Allow credentials
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));
app.use(express.json({ limit: '10mb' })); // Parse JSON bodies
app.use(express.raw({ type: 'application/json', limit: '10mb' })); // Allow large payloads for emails as raw

// Initialize database
createTable();

// Routes
app.use('/api/emails', emailRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});


module.exports = app;