const { Pool } = require('pg');

// Create a pool instance
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'phish_detection',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'password',
});

// Test connection
pool.on('connect', () => {
  console.log('Connected to PostgreSQL database');
});

pool.on('error', (err) => {
  console.error('Unexpected error on idle client', err);
  process.exit(-1);
});

// Create table if not exists
const createTable = async () => {
  const queries = [
    `CREATE TABLE IF NOT EXISTS emails (
      id SERIAL PRIMARY KEY,
      sender VARCHAR(255),
      recipient VARCHAR(255),
      subject TEXT,
      body TEXT,
      attachments JSONB,
      timestamp TIMESTAMP,
      phishing_score_cti FLOAT,
      cti_flags JSONB
    );`,
    `ALTER TABLE emails ADD COLUMN IF NOT EXISTS extracted_urls JSONB;`,
    `ALTER TABLE emails ADD COLUMN IF NOT EXISTS sender_domain VARCHAR(255);`,
    `ALTER TABLE emails ADD COLUMN IF NOT EXISTS sender_ip VARCHAR(45);`,
    `ALTER TABLE emails ADD COLUMN IF NOT EXISTS sender_name VARCHAR(255);`,
    `ALTER TABLE emails ADD COLUMN IF NOT EXISTS spf_result VARCHAR(50);`,
    `ALTER TABLE emails ADD COLUMN IF NOT EXISTS dkim_result VARCHAR(50);`,
    `ALTER TABLE emails ADD COLUMN IF NOT EXISTS dmarc_result VARCHAR(50);`,
    `ALTER TABLE emails ADD COLUMN IF NOT EXISTS headers JSONB;`,
    `ALTER TABLE emails ADD COLUMN IF NOT EXISTS attachment_hashes JSONB;`,
    `ALTER TABLE emails ADD COLUMN IF NOT EXISTS detailed_cti_analysis JSONB;`,
    `ALTER TABLE emails ADD COLUMN IF NOT EXISTS threat_summary JSONB;`,
    `ALTER TABLE emails ADD COLUMN IF NOT EXISTS cti_confidence VARCHAR(20);`,
    `CREATE TABLE IF NOT EXISTS blocked_senders (
      id SERIAL PRIMARY KEY,
      sender_email VARCHAR(255) UNIQUE NOT NULL,
      reason TEXT,
      blocked_by VARCHAR(255) DEFAULT 'system',
      blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`
  ];
  for (const query of queries) {
    try {
      await pool.query(query);
    } catch (err) {
      console.error('Error executing query:', query, err);
    }
  }
  console.log('Emails table created or updated');
};

// Save email data
const saveEmail = async (emailData) => {
  const query = `
    INSERT INTO emails (sender, recipient, subject, body, attachments, timestamp, phishing_score_cti, cti_flags, extracted_urls, sender_domain, sender_ip, sender_name, spf_result, dkim_result, dmarc_result, headers, attachment_hashes, detailed_cti_analysis, threat_summary, cti_confidence)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
    RETURNING id;
  `;
  const values = [
    emailData.sender,
    emailData.recipient,
    emailData.subject,
    emailData.body,
    JSON.stringify(emailData.attachments),
    emailData.timestamp,
    emailData.phishing_score_cti,
    JSON.stringify(emailData.cti_flags),
    JSON.stringify(emailData.extracted_urls),
    emailData.sender_domain,
    emailData.sender_ip,
    emailData.sender_name,
    emailData.spf_result,
    emailData.dkim_result,
    emailData.dmarc_result,
    JSON.stringify(emailData.headers),
    JSON.stringify(emailData.attachment_hashes),
    JSON.stringify(emailData.detailed_analysis || {}),
    JSON.stringify(emailData.threat_summary || {}),
    emailData.threat_summary?.confidence || 'unknown'
  ];
  try {
    const res = await pool.query(query, values);
    console.log('Email saved with ID:', res.rows[0].id);
    return res.rows[0].id;
  } catch (err) {
    console.error('Error saving email:', err);
    throw err;
  }
};

// Get all emails
const getEmails = async (filters = {}) => {
  let query = 'SELECT * FROM emails';
  const conditions = [];
  const values = [];
  let paramIndex = 1;

  // Build WHERE conditions based on filters
  if (filters.sender) {
    conditions.push(`sender ILIKE $${paramIndex}`);
    values.push(`%${filters.sender}%`);
    paramIndex++;
  }

  if (filters.subject) {
    conditions.push(`subject ILIKE $${paramIndex}`);
    values.push(`%${filters.subject}%`);
    paramIndex++;
  }

  if (filters.sender_domain) {
    conditions.push(`sender_domain = $${paramIndex}`);
    values.push(filters.sender_domain);
    paramIndex++;
  }

  if (filters.threat_level) {
    if (filters.threat_level === 'low') {
      conditions.push(`(phishing_score_cti < 0.4 OR phishing_score_cti IS NULL)`);
    } else if (filters.threat_level === 'medium') {
      conditions.push(`phishing_score_cti >= 0.4 AND phishing_score_cti < 0.7`);
    } else if (filters.threat_level === 'high') {
      conditions.push(`phishing_score_cti >= 0.7`);
    } else if (filters.threat_level === 'critical') {
      conditions.push(`phishing_score_cti >= 0.9`);
    } else {
      // For any other value, do exact match on the score if it's a number
      const score = parseFloat(filters.threat_level);
      if (!isNaN(score)) {
        conditions.push(`phishing_score_cti = $${paramIndex}`);
        values.push(score);
        paramIndex++;
      }
    }
  }

  if (filters.cti_confidence) {
    conditions.push(`cti_confidence = $${paramIndex}`);
    values.push(filters.cti_confidence);
    paramIndex++;
  }

  if (filters.start_date) {
    conditions.push(`timestamp >= $${paramIndex}`);
    values.push(filters.start_date);
    paramIndex++;
  }

  if (filters.end_date) {
    conditions.push(`timestamp <= $${paramIndex}`);
    values.push(filters.end_date);
    paramIndex++;
  }

  if (filters.has_attachments === 'true') {
    conditions.push(`jsonb_array_length(attachments) > 0`);
  } else if (filters.has_attachments === 'false') {
    conditions.push(`(attachments IS NULL OR jsonb_array_length(attachments) = 0)`);
  }

  if (conditions.length > 0) {
    query += ' WHERE ' + conditions.join(' AND ');
  }

  query += ' ORDER BY timestamp DESC;';

  try {
    const res = await pool.query(query, values);
    return res.rows.map(row => {
      let attachments = [];
      try {
        attachments = typeof row.attachments === 'string' ? JSON.parse(row.attachments) : (row.attachments || []);
      } catch (e) {
        console.warn('Failed to parse attachments for email ID:', row.id, e);
        attachments = [];
      }
      let cti_flags = [];
      try {
        cti_flags = typeof row.cti_flags === 'string' ? JSON.parse(row.cti_flags) : (row.cti_flags || []);
      } catch (e) {
        console.warn('Failed to parse cti_flags for email ID:', row.id, e);
        // Handle old data where it might be a string or malformed
        if (typeof row.cti_flags === 'string') {
          cti_flags = row.cti_flags.split(',').map(s => s.trim());
        } else {
          cti_flags = [];
        }
      }
      let extracted_urls = [];
      try {
        extracted_urls = typeof row.extracted_urls === 'string' ? JSON.parse(row.extracted_urls) : (row.extracted_urls || []);
      } catch (e) {
        console.warn('Failed to parse extracted_urls for email ID:', row.id, e);
        // Handle old data where it might be a string
        if (typeof row.extracted_urls === 'string') {
          extracted_urls = row.extracted_urls.split(',').map(s => s.trim());
        } else {
          extracted_urls = [];
        }
      }
      let headers = {};
      try {
        headers = typeof row.headers === 'string' ? JSON.parse(row.headers) : (row.headers || {});
      } catch (e) {
        console.warn('Failed to parse headers for email ID:', row.id, e);
        headers = {};
      }
      let attachment_hashes = [];
      try {
        attachment_hashes = typeof row.attachment_hashes === 'string' ? JSON.parse(row.attachment_hashes) : (row.attachment_hashes || []);
      } catch (e) {
        console.warn('Failed to parse attachment_hashes for email ID:', row.id, e);
        attachment_hashes = [];
      }
      let detailed_analysis = {};
      try {
        detailed_analysis = typeof row.detailed_cti_analysis === 'string' ? JSON.parse(row.detailed_cti_analysis) : (row.detailed_cti_analysis || {});
      } catch (e) {
        console.warn('Failed to parse detailed_cti_analysis for email ID:', row.id, e);
        detailed_analysis = {};
      }
      let threat_summary = {};
      try {
        threat_summary = typeof row.threat_summary === 'string' ? JSON.parse(row.threat_summary) : (row.threat_summary || {});
      } catch (e) {
        console.warn('Failed to parse threat_summary for email ID:', row.id, e);
        threat_summary = {};
      }
      return {
        ...row,
        attachments,
        cti_flags,
        extracted_urls,
        headers,
        attachment_hashes,
        detailed_analysis,
        threat_summary
      };
    });
  } catch (err) {
    console.error('Error fetching emails:', err);
    throw err;
  }
};

// Delete a single email by ID
const deleteEmail = async (id) => {
  const query = 'DELETE FROM emails WHERE id = $1 RETURNING id;';
  try {
    const res = await pool.query(query, [id]);
    if (res.rows.length > 0) {
      console.log('Email deleted with ID:', res.rows[0].id);
      return res.rows[0].id;
    } else {
      throw new Error('Email not found');
    }
  } catch (err) {
    console.error('Error deleting email:', err);
    throw err;
  }
};

// Delete multiple emails by IDs
const deleteEmails = async (ids) => {
  if (!Array.isArray(ids) || ids.length === 0) {
    throw new Error('IDs must be a non-empty array');
  }
  const query = 'DELETE FROM emails WHERE id = ANY($1) RETURNING id;';
  try {
    const res = await pool.query(query, [ids]);
    console.log('Emails deleted with IDs:', res.rows.map(row => row.id));
    return res.rows.map(row => row.id);
  } catch (err) {
    console.error('Error deleting emails:', err);
    throw err;
  }
};

// Block a sender email
const blockSender = async (senderEmail, reason = 'Manual block', blockedBy = 'system') => {
  const query = `
    INSERT INTO blocked_senders (sender_email, reason, blocked_by)
    VALUES ($1, $2, $3)
    ON CONFLICT (sender_email) DO NOTHING
    RETURNING id;
  `;
  const values = [senderEmail, reason, blockedBy];
  try {
    const res = await pool.query(query, values);
    if (res.rows.length > 0) {
      console.log('Sender blocked with ID:', res.rows[0].id);
      return res.rows[0].id;
    } else {
      console.log('Sender already blocked:', senderEmail);
      return null; // Already exists
    }
  } catch (err) {
    console.error('Error blocking sender:', err);
    throw err;
  }
};

// Get all blocked senders
const getBlockedSenders = async () => {
  const query = 'SELECT * FROM blocked_senders ORDER BY blocked_at DESC;';
  try {
    const res = await pool.query(query);
    return res.rows;
  } catch (err) {
    console.error('Error fetching blocked senders:', err);
    throw err;
  }
};

// Check if a sender is blocked
const isSenderBlocked = async (senderEmail) => {
  const query = 'SELECT id FROM blocked_senders WHERE sender_email = $1;';
  try {
    const res = await pool.query(query, [senderEmail]);
    return res.rows.length > 0;
  } catch (err) {
    console.error('Error checking if sender is blocked:', err);
    throw err;
  }
};

// Unblock a sender
const unblockSender = async (senderEmail) => {
  const query = 'DELETE FROM blocked_senders WHERE sender_email = $1 RETURNING id;';
  try {
    const res = await pool.query(query, [senderEmail]);
    if (res.rows.length > 0) {
      console.log('Sender unblocked with ID:', res.rows[0].id);
      return res.rows[0].id;
    } else {
      throw new Error('Sender not found in blocked list');
    }
  } catch (err) {
    console.error('Error unblocking sender:', err);
    throw err;
  }
};

module.exports = {
  pool,
  createTable,
  saveEmail,
  getEmails,
  deleteEmail,
  deleteEmails,
  blockSender,
  getBlockedSenders,
  isSenderBlocked,
  unblockSender
};
