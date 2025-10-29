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
    );`,
    // Performance indexes for common queries
    `CREATE INDEX IF NOT EXISTS idx_emails_sender ON emails(sender);`,
    `CREATE INDEX IF NOT EXISTS idx_emails_sender_domain ON emails(sender_domain);`,
    `CREATE INDEX IF NOT EXISTS idx_emails_timestamp ON emails(timestamp DESC);`,
    `CREATE INDEX IF NOT EXISTS idx_emails_phishing_score ON emails(phishing_score_cti);`,
    `CREATE INDEX IF NOT EXISTS idx_emails_cti_confidence ON emails(cti_confidence);`,
    `CREATE INDEX IF NOT EXISTS idx_emails_subject ON emails USING gin(to_tsvector('english', subject));`,
    `CREATE INDEX IF NOT EXISTS idx_blocked_senders_email ON blocked_senders(sender_email);`
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
const getEmails = async (filters = {}, options = {}) => {
  const { limit = 50, offset = 0, fields = null } = options;

  // Define available fields for selective retrieval
  const allFields = [
    'id', 'sender', 'recipient', 'subject', 'body', 'attachments', 'timestamp',
    'phishing_score_cti', 'cti_flags', 'extracted_urls', 'sender_domain',
    'sender_ip', 'sender_name', 'spf_result', 'dkim_result', 'dmarc_result',
    'headers', 'attachment_hashes', 'detailed_cti_analysis', 'threat_summary', 'cti_confidence'
  ];

  // Use selective fields if specified, otherwise use all fields
  const selectFields = fields && Array.isArray(fields) ? fields : allFields;
  const selectClause = selectFields.join(', ');

  let query = `SELECT ${selectClause} FROM emails`;
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

  query += ' ORDER BY timestamp DESC';

  // Add pagination
  query += ` LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
  values.push(limit, offset);

  try {
    const res = await pool.query(query, values);

    // Get total count for pagination metadata
    let countQuery = 'SELECT COUNT(*) as total FROM emails';
    if (conditions.length > 0) {
      countQuery += ' WHERE ' + conditions.join(' AND ');
    }
    const countRes = await pool.query(countQuery, values.slice(0, -2)); // Remove limit and offset from values
    const total = parseInt(countRes.rows[0].total);

    return {
      emails: res.rows.map(row => {
        // Only parse JSON fields if they were selected
        let result = { ...row };

        if (selectFields.includes('attachments')) {
          let attachments = [];
          try {
            attachments = typeof row.attachments === 'string' ? JSON.parse(row.attachments) : (row.attachments || []);
          } catch (e) {
            console.warn('Failed to parse attachments for email ID:', row.id, e);
            attachments = [];
          }
          result.attachments = attachments;
        }

        if (selectFields.includes('cti_flags')) {
          let cti_flags = [];
          try {
            cti_flags = typeof row.cti_flags === 'string' ? JSON.parse(row.cti_flags) : (row.cti_flags || []);
          } catch (e) {
            console.warn('Failed to parse cti_flags for email ID:', row.id, e);
            if (typeof row.cti_flags === 'string') {
              cti_flags = row.cti_flags.split(',').map(s => s.trim());
            } else {
              cti_flags = [];
            }
          }
          result.cti_flags = cti_flags;
        }

        if (selectFields.includes('extracted_urls')) {
          let extracted_urls = [];
          try {
            extracted_urls = typeof row.extracted_urls === 'string' ? JSON.parse(row.extracted_urls) : (row.extracted_urls || []);
          } catch (e) {
            console.warn('Failed to parse extracted_urls for email ID:', row.id, e);
            if (typeof row.extracted_urls === 'string') {
              extracted_urls = row.extracted_urls.split(',').map(s => s.trim());
            } else {
              extracted_urls = [];
            }
          }
          result.extracted_urls = extracted_urls;
        }

        if (selectFields.includes('headers')) {
          let headers = {};
          try {
            headers = typeof row.headers === 'string' ? JSON.parse(row.headers) : (row.headers || {});
          } catch (e) {
            console.warn('Failed to parse headers for email ID:', row.id, e);
            headers = {};
          }
          result.headers = headers;
        }

        if (selectFields.includes('attachment_hashes')) {
          let attachment_hashes = [];
          try {
            attachment_hashes = typeof row.attachment_hashes === 'string' ? JSON.parse(row.attachment_hashes) : (row.attachment_hashes || []);
          } catch (e) {
            console.warn('Failed to parse attachment_hashes for email ID:', row.id, e);
            attachment_hashes = [];
          }
          result.attachment_hashes = attachment_hashes;
        }

        if (selectFields.includes('detailed_cti_analysis')) {
          let detailed_analysis = {};
          try {
            detailed_analysis = typeof row.detailed_cti_analysis === 'string' ? JSON.parse(row.detailed_cti_analysis) : (row.detailed_cti_analysis || {});
          } catch (e) {
            console.warn('Failed to parse detailed_cti_analysis for email ID:', row.id, e);
            detailed_analysis = {};
          }
          result.detailed_analysis = detailed_analysis;
        }

        if (selectFields.includes('threat_summary')) {
          let threat_summary = {};
          try {
            threat_summary = typeof row.threat_summary === 'string' ? JSON.parse(row.threat_summary) : (row.threat_summary || {});
          } catch (e) {
            console.warn('Failed to parse threat_summary for email ID:', row.id, e);
            threat_summary = {};
          }
          result.threat_summary = threat_summary;
        }

        return result;
      }),
      pagination: {
        total,
        limit,
        offset,
        hasMore: offset + limit < total
      }
    };
  } catch (err) {
    console.error('Error fetching emails:', err);
    throw err;
  }
};

// Get email intelligence data (aggregated by sender)
const getEmailIntelligence = async (filters = {}, options = {}) => {
  const { limit = 50, offset = 0, blockedFilter = 'all' } = options; // 'all', 'blocked', 'non-blocked'

  // Helper function to extract clean email from formatted addresses
  const extractEmailAddress = (emailString) => {
    // Handle "Name <email@domain.com>" format
    const angleBracketMatch = emailString.match(/<([^>]+)>/);
    if (angleBracketMatch) {
      return angleBracketMatch[1];
    }
    // Handle "email@domain.com" format
    return emailString.trim();
  };

  // Build base query to get all emails with necessary fields
  let query = `
    SELECT
      sender,
      sender_name,
      sender_domain,
      sender_ip,
      detailed_cti_analysis,
      threat_summary,
      timestamp,
      phishing_score_cti
    FROM emails
    WHERE sender IS NOT NULL AND sender != ''
  `;

  const conditions = [];
  const values = [];
  let paramIndex = 1;

  // Add filters
  if (filters.sender_domain) {
    conditions.push(`sender_domain = $${paramIndex}`);
    values.push(filters.sender_domain);
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

  if (conditions.length > 0) {
    query += ' AND ' + conditions.join(' AND ');
  }

  query += ' ORDER BY sender, timestamp DESC';

  try {
    const res = await pool.query(query, values);

    // Group emails by sender and calculate intelligence
    const senderGroups = {};
    res.rows.forEach(row => {
      const sender = row.sender;
      if (!senderGroups[sender]) {
        senderGroups[sender] = [];
      }
      senderGroups[sender].push(row);
    });

    // Get blocked senders for is_blocked field (always needed)
    const blockedRes = await pool.query('SELECT sender_email FROM blocked_senders');
    const allBlockedSenders = new Set(blockedRes.rows.map(row => row.sender_email));

    // Get blocked senders for filtering (if needed)
    let blockedSenders = new Set();
    if (blockedFilter !== 'all') {
      blockedSenders = allBlockedSenders;
    }

    // Calculate intelligence for each sender
    const intelligenceData = Object.entries(senderGroups).map(([senderEmail, emails]) => {
      try {
      // Extract clean email and domain
      const cleanEmail = extractEmailAddress(senderEmail);
      const domain = cleanEmail.includes('@') ? cleanEmail.split('@')[1] : 
        (emails[0]?.sender_domain || 'unknown');        // Get domain analysis data from the most recent email that has it
        const domainAnalysis = emails
          .filter(email => {
            try {
              const analysis = typeof email.detailed_cti_analysis === 'string' ?
                JSON.parse(email.detailed_cti_analysis) : email.detailed_cti_analysis;
              return analysis?.domains?.[domain];
            } catch (e) {
              return false;
            }
          })
          .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())[0];

        let parsedAnalysis = null;
        if (domainAnalysis) {
          try {
            parsedAnalysis = typeof domainAnalysis.detailed_cti_analysis === 'string' ?
              JSON.parse(domainAnalysis.detailed_cti_analysis) : domainAnalysis.detailed_cti_analysis;
          } catch (e) {
            parsedAnalysis = null;
          }
        }

      const domainData = parsedAnalysis?.domains?.[domain];

      // Get IP analysis data - look at all IPs in the analysis, not just sender_ip
      let ipData = null;
      let allIPData = [];
      if (domainAnalysis) {
        try {
          const parsedIPAnalysis = typeof domainAnalysis.detailed_cti_analysis === 'string' ?
            JSON.parse(domainAnalysis.detailed_cti_analysis) : domainAnalysis.detailed_cti_analysis;

          // Get all IP data from the analysis
          if (parsedIPAnalysis?.ips) {
            allIPData = Object.values(parsedIPAnalysis.ips);
            // Find the IP with highest threat level or most malicious detections
            ipData = allIPData.reduce((worst, current) => {
              const currentMalicious = current.stats?.malicious || 0;
              const worstMalicious = worst?.stats?.malicious || 0;
              const currentThreatLevel = current.threat_level === 'high' || current.threat_level === 'critical' ? 3 :
                                        current.threat_level === 'medium' ? 2 : 1;
              const worstThreatLevel = worst?.threat_level === 'high' || worst?.threat_level === 'critical' ? 3 :
                                      worst?.threat_level === 'medium' ? 2 : 1;

              if (currentThreatLevel > worstThreatLevel) return current;
              if (currentThreatLevel === worstThreatLevel && currentMalicious > worstMalicious) return current;
              return worst;
            }, null);
          }
        } catch (e) {
          ipData = null;
          allIPData = [];
        }
      }        // Calculate malicious engines count (combine domain and IP analysis)
        const domainMaliciousCount = domainData?.stats?.malicious || 0;
        const ipMaliciousCount = ipData?.stats?.malicious || 0;
        const maliciousEnginesCount = Math.max(domainMaliciousCount, ipMaliciousCount); // Use the higher count

        // Extract actual malicious engine names from domain and all IP analysis
        const domainMaliciousEngines = domainData?.malicious_engines?.map(engine => engine.engine) || [];
        const ipMaliciousEngines = ipData?.malicious_engines?.map(engine => engine.engine) || [];

        // Also extract engines from all analyzed IPs (not just the primary one)
        const allIPMaliciousEngines = allIPData.flatMap(ip =>
          ip.malicious_engines?.map(engine => engine.engine) || []
        );

        const maliciousEngines = [...new Set([...domainMaliciousEngines, ...ipMaliciousEngines, ...allIPMaliciousEngines])];

        const domainTotalEngines = domainData?.stats ?
          (domainData.stats.malicious + domainData.stats.suspicious + domainData.stats.harmless + domainData.stats.undetected) : 60;
        const ipTotalEngines = ipData?.stats ?
          (ipData.stats.malicious + ipData.stats.suspicious + ipData.stats.harmless + ipData.stats.undetected) : 60;
        const totalEngines = Math.max(domainTotalEngines, ipTotalEngines); // Use the higher total

        // Check if any emails from this sender are malicious
        const hasMaliciousEmails = emails.some(email => {
          try {
            const threatSummary = typeof email.threat_summary === 'string' ?
              JSON.parse(email.threat_summary) : email.threat_summary;
            return threatSummary?.overall_risk === 'high' || threatSummary?.overall_risk === 'critical';
          } catch (e) {
            return false;
          }
        });

        // Calculate reputation score (use domain first, then IP as fallback)
        const reputationScore = domainData?.reputation_score ??
          ipData?.reputation_score ??
          Math.max(0, Math.round(100 - (maliciousEnginesCount / Math.max(totalEngines, 1)) * 100));

      // Determine threat level (consider both domain and all IP analysis)
      let threatLevel = 'clean';
      let threatReasons = [];

      // Check all IP threat levels first
      const maliciousIPs = allIPData.filter(ip => ip.threat_level === 'high' || ip.threat_level === 'critical');
      if (maliciousIPs.length > 0) {
        threatLevel = 'malicious';
        const allIPEngines = maliciousIPs.flatMap(ip => ip.malicious_engines?.map(engine => engine.engine) || []);
        const uniqueIPEngines = [...new Set(allIPEngines)];
        threatReasons.push(`IP flagged by ${uniqueIPEngines.length > 0 ? uniqueIPEngines.slice(0, 3).join(', ') + (uniqueIPEngines.length > 3 ? '...' : '') : 'multiple engines'}`);
      } else {
        // Check for medium threat IPs if no high/critical
        const mediumIPs = allIPData.filter(ip => ip.threat_level === 'medium');
        if (mediumIPs.length > 0 && threatLevel === 'clean') {
          threatLevel = 'suspicious';
          threatReasons.push(`IP analysis shows medium threat level`);
        }
      }

      // Check domain threat level
      if (domainData?.threat_level) {
        const domainRisk = domainData.threat_level;
        if (domainRisk === 'high' || domainRisk === 'critical') {
          threatLevel = 'malicious';
          const domainEngines = domainData.malicious_engines?.map(engine => engine.engine) || [];
          threatReasons.push(`Domain flagged by ${domainEngines.length > 0 ? domainEngines.slice(0, 3).join(', ') + (domainEngines.length > 3 ? '...' : '') : 'multiple engines'}`);
        } else if (domainRisk === 'medium' && threatLevel === 'clean') {
          threatLevel = 'suspicious';
          threatReasons.push(`Domain analysis shows medium threat level`);
        }
      }

      // Fallback to email-based logic if no domain/IP analysis
      if (threatLevel === 'clean') {
        if (hasMaliciousEmails) {
          threatLevel = 'malicious';
          threatReasons.push('Contains emails with high phishing scores');
        } else if (reputationScore < 70) {
          threatLevel = 'suspicious';
          threatReasons.push(`Low reputation score (${reputationScore})`);
        } else {
          threatReasons.push('No significant threats detected');
        }
      }        // Get date range
        const timestamps = emails.map(email => new Date(email.timestamp).getTime()).filter(t => !isNaN(t));
        const firstSeen = timestamps.length > 0 ? new Date(Math.min(...timestamps)).toISOString() : new Date().toISOString();
        const lastSeen = timestamps.length > 0 ? new Date(Math.max(...timestamps)).toISOString() : new Date().toISOString();

        // Check if sender is blocked (comprehensive check)
        const isBlocked = allBlockedSenders.has(senderEmail) ||
                         allBlockedSenders.has(cleanEmail) ||
                         Array.from(allBlockedSenders).some(blockedEmail =>
                           blockedEmail.includes(senderEmail) || blockedEmail.includes(cleanEmail)
                         );

        return {
          email: senderEmail,
          domain,
          reputation_score: reputationScore,
          threat_level: threatLevel,
          threat_reasons: threatReasons,
          first_seen: firstSeen,
          last_seen: lastSeen,
          email_count: emails.length,
          malicious_engines: maliciousEngines,
          total_engines: totalEngines,
          categories: [...new Set([
            ...(Array.isArray(domainData?.categories) ? domainData.categories : []),
            ...(Array.isArray(ipData?.categories) ? ipData.categories : [])
          ])],
          sender_name: emails[0]?.sender_name,
          is_blocked: isBlocked
        };
      } catch (error) {
        console.error('Error processing intelligence for sender:', senderEmail, error);
        // Return a safe fallback
        return {
          email: senderEmail,
          domain: 'unknown',
          reputation_score: 50,
          threat_level: 'unknown',
          threat_reasons: ['Analysis failed due to error'],
          first_seen: new Date().toISOString(),
          last_seen: new Date().toISOString(),
          email_count: emails.length,
          malicious_engines: [],
          total_engines: 60,
          categories: [],
          sender_name: null,
          is_blocked: false,
          error: error.message
        };
      }
    });

    // Apply blocked filter
    let filteredData = intelligenceData;
    if (blockedFilter === 'blocked') {
      filteredData = intelligenceData.filter(item => item.is_blocked);
    } else if (blockedFilter === 'non-blocked') {
      filteredData = intelligenceData.filter(item => !item.is_blocked);
    }

    // Sort by threat level (malicious first), then by email count
    filteredData.sort((a, b) => {
      const threatOrder = { malicious: 3, suspicious: 2, clean: 1, unknown: 0 };
      const aThreat = threatOrder[a.threat_level] || 0;
      const bThreat = threatOrder[b.threat_level] || 0;
      if (aThreat !== bThreat) return bThreat - aThreat;
      return b.email_count - a.email_count;
    });

    // Apply pagination
    const total = filteredData.length;
    const paginatedData = filteredData.slice(offset, offset + limit);

    return {
      intelligence: paginatedData,
      pagination: {
        total,
        limit,
        offset,
        hasMore: offset + limit < total
      }
    };
  } catch (err) {
    console.error('Error fetching email intelligence:', err);
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
  // First check for exact match
  const exactQuery = 'SELECT id FROM blocked_senders WHERE sender_email = $1;';
  try {
    const exactRes = await pool.query(exactQuery, [senderEmail]);
    if (exactRes.rows.length > 0) {
      return true;
    }

    // If no exact match, check if any blocked email contains this email in angle brackets
    // This handles cases where blocked list has "Name <email>" but query is just "email"
    const containsQuery = 'SELECT id FROM blocked_senders WHERE sender_email LIKE $1;';
    const pattern = `%${senderEmail}%`;
    const containsRes = await pool.query(containsQuery, [pattern]);
    if (containsRes.rows.length > 0) {
      return true;
    }

    // Also check if this email matches any plain email addresses (without display names)
    // Extract email from angle brackets if present
    const angleBracketMatch = senderEmail.match(/<([^>]+)>/);
    if (angleBracketMatch) {
      const plainEmail = angleBracketMatch[1];
      const plainRes = await pool.query(exactQuery, [plainEmail]);
      if (plainRes.rows.length > 0) {
        return true;
      }
    }

    return false;
  } catch (err) {
    console.error('Error checking if sender is blocked:', err);
    throw err;
  }
};

// Unblock a sender
const unblockSender = async (senderEmail) => {
  // First try exact match
  let query = 'DELETE FROM blocked_senders WHERE sender_email = $1 RETURNING id;';
  try {
    let res = await pool.query(query, [senderEmail]);
    if (res.rows.length > 0) {
      console.log('Sender unblocked with ID:', res.rows[0].id);
      return res.rows[0].id;
    }

    // If no exact match, check if any blocked email contains this email in angle brackets
    // This handles cases where blocked list has "Name <email>" but query is just "email"
    const containsQuery = 'SELECT sender_email FROM blocked_senders WHERE sender_email LIKE $1;';
    const pattern = `%${senderEmail}%`;
    const containsRes = await pool.query(containsQuery, [pattern]);
    if (containsRes.rows.length > 0) {
      // Delete the first matching entry
      const deleteQuery = 'DELETE FROM blocked_senders WHERE sender_email = $1 RETURNING id;';
      res = await pool.query(deleteQuery, [containsRes.rows[0].sender_email]);
      if (res.rows.length > 0) {
        console.log('Sender unblocked with ID:', res.rows[0].id);
        return res.rows[0].id;
      }
    }

    // Also check if this email matches any plain email addresses (without display names)
    // Extract email from angle brackets if present
    const angleBracketMatch = senderEmail.match(/<([^>]+)>/);
    if (angleBracketMatch) {
      const plainEmail = angleBracketMatch[1];
      res = await pool.query(query, [plainEmail]);
      if (res.rows.length > 0) {
        console.log('Sender unblocked with ID:', res.rows[0].id);
        return res.rows[0].id;
      }
    }

    throw new Error('Sender not found in blocked list');
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
  getEmailIntelligence,
  deleteEmail,
  deleteEmails,
  blockSender,
  getBlockedSenders,
  isSenderBlocked,
  unblockSender
};
