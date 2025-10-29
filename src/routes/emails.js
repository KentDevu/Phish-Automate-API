const express = require('express');
const { parseEmail, getDomain, extractSenderIP } = require('../parser');
const { checkCTI } = require('../cti');
const { saveEmail, getEmails, deleteEmail, deleteEmails, blockSender, getBlockedSenders, isSenderBlocked, unblockSender, getEmailIntelligence } = require('../db');

const router = express.Router();

/**
 * POST /api/emails
 * Receives raw email data, processes it, and returns structured JSON
 * Accepts either:
 * - Raw email string as request body
 * - JSON object/array with rawEmail field(s)
 */
router.post('/', async (req, res) => {
  try {
    let body = req.body;
    if (Buffer.isBuffer(body)) {
      body = JSON.parse(body.toString());
    }
    // Handle n8n HTTP Request format where body is wrapped
    if (body && typeof body === 'object' && body.body) {
      body = body.body;
    }
    console.log('Parsed body:', body);
    console.log('Body type:', typeof body);
    console.log('Is array:', Array.isArray(body));
    let emailsToProcess = [];

    if (typeof body === 'string') {
      // Raw email string sent directly
      emailsToProcess = [{ rawEmail: body }];
    } else if (Array.isArray(body)) {
      // Array of email objects
      emailsToProcess = body;
    } else if (body && typeof body === 'object' && body.rawEmail) {
      // Single email object
      emailsToProcess = [body];
    } else {
      return res.status(400).json({ error: 'Invalid request format. Send raw email string or JSON with rawEmail field(s)' });
    }

    // Merge binary into rawEmail if present
    emailsToProcess.forEach(emailData => {
      if (emailData.binary && emailData.rawEmail && typeof emailData.rawEmail === 'object') {
        emailData.rawEmail.binary = emailData.binary;
      }
    });

    const results = await Promise.all(emailsToProcess.map(async (emailData) => {
      let parsedEmail;
      if (emailData.rawEmail) {
        // Parse the email data (string or object)
        parsedEmail = await parseEmail(emailData.rawEmail);
      } else {
        throw new Error('Invalid email data format');
      }
      const ctiResult = await checkCTI(parsedEmail);
      const result = {
        ...parsedEmail,
        ...ctiResult
      };
      // Save to database
      await saveEmail(result);
      return result;
    }));

    // Return single object if only one email, array if multiple
    res.json(results.length === 1 ? results[0] : results);
  } catch (error) {
    console.error('Error processing email:', error);
    res.status(500).json({ error: 'Failed to process email', details: error.message });
  }
});

/**
 * GET /api/emails/all
 * Retrieve all processed emails from the database with optional filtering
 * Query parameters:
 * - sender: Filter by sender email (partial match)
 * - subject: Filter by subject (partial match)
 * - sender_domain: Filter by sender domain (exact match)
 * - threat_level: Filter by threat level (exact match)
 * - cti_confidence: Filter by CTI confidence (exact match)
 * - start_date: Filter emails from this date onwards (ISO format)
 * - end_date: Filter emails up to this date (ISO format)
 * - has_attachments: Filter by attachment presence ('true' or 'false')
 */
router.get('/all', async (req, res) => {
  try {
    const filters = {};
    if (req.query.sender) filters.sender = req.query.sender;
    if (req.query.subject) filters.subject = req.query.subject;
    if (req.query.sender_domain) filters.sender_domain = req.query.sender_domain;
    if (req.query.threat_level) filters.threat_level = req.query.threat_level;
    if (req.query.cti_confidence) filters.cti_confidence = req.query.cti_confidence;
    if (req.query.start_date) filters.start_date = req.query.start_date;
    if (req.query.end_date) filters.end_date = req.query.end_date;
    if (req.query.has_attachments) filters.has_attachments = req.query.has_attachments;

    // Pagination options
    const options = {
      limit: req.query.limit ? parseInt(req.query.limit) : 50,
      offset: req.query.offset ? parseInt(req.query.offset) : 0,
      fields: req.query.fields ? req.query.fields.split(',') : null
    };

    // Validate pagination parameters
    if (options.limit < 1 || options.limit > 1000) {
      return res.status(400).json({ error: 'Limit must be between 1 and 1000' });
    }
    if (options.offset < 0) {
      return res.status(400).json({ error: 'Offset must be non-negative' });
    }

    const result = await getEmails(filters, options);
    res.json(result);
  } catch (error) {
    console.error('Error fetching emails:', error);
    res.status(500).json({ error: 'Failed to fetch emails' });
  }
});


/**
 * GET /api/emails/summary
 * Get a lightweight summary of emails for listing (faster than /all)
 * Supports pagination and filtering
 * Query parameters: limit, offset, sender, subject, sender_domain, threat_level, cti_confidence, start_date, end_date, has_attachments
 */
router.get('/summary', async (req, res) => {
  try {
    const filters = {};
    if (req.query.sender) filters.sender = req.query.sender;
    if (req.query.subject) filters.subject = req.query.subject;
    if (req.query.sender_domain) filters.sender_domain = req.query.sender_domain;
    if (req.query.threat_level) filters.threat_level = req.query.threat_level;
    if (req.query.cti_confidence) filters.cti_confidence = req.query.cti_confidence;
    if (req.query.start_date) filters.start_date = req.query.start_date;
    if (req.query.end_date) filters.end_date = req.query.end_date;
    if (req.query.has_attachments) filters.has_attachments = req.query.has_attachments;

    // Pagination options with summary fields only
    const options = {
      limit: req.query.limit ? parseInt(req.query.limit) : 50,
      offset: req.query.offset ? parseInt(req.query.offset) : 0,
      fields: ['id', 'sender', 'subject', 'timestamp', 'phishing_score_cti', 'threat_summary', 'cti_confidence', 'sender_domain']
    };

    // Validate pagination parameters
    if (options.limit < 1 || options.limit > 1000) {
      return res.status(400).json({ error: 'Limit must be between 1 and 1000' });
    }
    if (options.offset < 0) {
      return res.status(400).json({ error: 'Offset must be non-negative' });
    }

    const result = await getEmails(filters, options);
    res.json(result);
  } catch (error) {
    console.error('Error fetching email summaries:', error);
    res.status(500).json({ error: 'Failed to fetch email summaries' });
  }
});


/**
 * GET /api/emails/intelligence
 * Get aggregated email intelligence data grouped by sender
 * Query parameters: limit, offset, sender_domain, start_date, end_date, blocked (all/blocked/non-blocked)
 */
router.get('/intelligence', async (req, res) => {
  try {
    const filters = {};
    if (req.query.sender_domain) filters.sender_domain = req.query.sender_domain;
    if (req.query.start_date) filters.start_date = req.query.start_date;
    if (req.query.end_date) filters.end_date = req.query.end_date;

    // Pagination and filtering options
    const options = {
      limit: req.query.limit ? parseInt(req.query.limit) : 50,
      offset: req.query.offset ? parseInt(req.query.offset) : 0,
      blockedFilter: req.query.blocked || 'all' // 'all', 'blocked', 'non-blocked'
    };

    // Validate parameters
    if (options.limit < 1 || options.limit > 1000) {
      return res.status(400).json({ error: 'Limit must be between 1 and 1000' });
    }
    if (options.offset < 0) {
      return res.status(400).json({ error: 'Offset must be non-negative' });
    }
    if (!['all', 'blocked', 'non-blocked'].includes(options.blockedFilter)) {
      return res.status(400).json({ error: 'Blocked filter must be one of: all, blocked, non-blocked' });
    }

    const result = await getEmailIntelligence(filters, options);
    res.json(result);
  } catch (error) {
    console.error('Error fetching email intelligence:', error);
    res.status(500).json({ error: 'Failed to fetch email intelligence' });
  }
});


/**
 * DELETE /api/emails/:id
 * Delete a single email by ID
 */
router.delete('/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) {
      return res.status(400).json({ error: 'Invalid ID' });
    }
    await deleteEmail(id);
    res.json({ message: 'Email deleted successfully' });
  } catch (error) {
    console.error('Error deleting email:', error);
    if (error.message === 'Email not found') {
      res.status(404).json({ error: 'Email not found' });
    } else {
      res.status(500).json({ error: 'Failed to delete email' });
    }
  }
});

/**
 * DELETE /api/emails/bulk
 * Delete multiple emails by IDs (expects { ids: [1,2,3] } in body)
 */
router.delete('/bulk', async (req, res) => {
  try {
    const { ids } = req.body;
    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: 'IDs must be a non-empty array' });
    }
    const deletedIds = await deleteEmails(ids);
    res.json({ message: 'Emails deleted successfully', deletedIds });
  } catch (error) {
    console.error('Error deleting emails:', error);
    res.status(500).json({ error: 'Failed to delete emails' });
  }
});

/**
 * POST /api/emails/block
 * Block a sender email address
 */
router.post('/block', async (req, res) => {
  try {
    const { sender_email, reason, blocked_by } = req.body;

    if (!sender_email) {
      return res.status(400).json({ error: 'sender_email is required' });
    }

    const id = await blockSender(sender_email, reason, blocked_by);
    if (id) {
      res.json({ message: 'Sender blocked successfully', id });
    } else {
      res.json({ message: 'Sender was already blocked' });
    }
  } catch (error) {
    console.error('Error blocking sender:', error);
    res.status(500).json({ error: 'Failed to block sender' });
  }
});

/**
 * GET /api/emails/blocked
 * Get all blocked sender emails
 */
router.get('/blocked', async (req, res) => {
  try {
    const blockedSenders = await getBlockedSenders();
    res.json(blockedSenders);
  } catch (error) {
    console.error('Error fetching blocked senders:', error);
    res.status(500).json({ error: 'Failed to fetch blocked senders' });
  }
});

/**
 * GET /api/emails/blocked/:email
 * Check if a specific sender email is blocked
 */
router.get('/blocked/:email', async (req, res) => {
  try {
    const email = decodeURIComponent(req.params.email);
    const isBlocked = await isSenderBlocked(email);
    res.json({ email, is_blocked: isBlocked });
  } catch (error) {
    console.error('Error checking sender block status:', error);
    res.status(500).json({ error: 'Failed to check sender block status' });
  }
});

/**
 * DELETE /api/emails/blocked/:senderemail
 * Unblock a sender email address
 */
router.delete('/blocked/:senderemail', async (req, res) => {
  try {
    const email = decodeURIComponent(req.params.senderemail);
    await unblockSender(email);
    res.json({ message: 'Sender unblocked successfully' });
  } catch (error) {
    console.error('Error unblocking sender:', error);
    if (error.message === 'Sender not found in blocked list') {
      res.status(404).json({ error: 'Sender not found in blocked list' });
    } else {
      res.status(500).json({ error: 'Failed to unblock sender' });
    }
  }
});


module.exports = router;