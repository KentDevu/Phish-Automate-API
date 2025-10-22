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
    `ALTER TABLE emails ADD COLUMN IF NOT EXISTS attachment_hashes JSONB;`
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
    INSERT INTO emails (sender, recipient, subject, body, attachments, timestamp, phishing_score_cti, cti_flags, extracted_urls, sender_domain, sender_ip, sender_name, spf_result, dkim_result, dmarc_result, headers, attachment_hashes)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
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
    JSON.stringify(emailData.attachment_hashes)
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
const getEmails = async () => {
  const query = 'SELECT * FROM emails ORDER BY timestamp DESC;';
  try {
    const res = await pool.query(query);
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
      return {
        ...row,
        attachments,
        cti_flags,
        extracted_urls,
        headers,
        attachment_hashes
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

module.exports = {
  pool,
  createTable,
  saveEmail,
  getEmails,
  deleteEmail,
  deleteEmails
};
