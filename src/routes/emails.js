const express = require('express');
const { parseEmail, getDomain, extractSenderIP } = require('../parser');
const { checkCTI } = require('../cti');
const { saveEmail, getEmails } = require('../db');

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
 * Retrieve all processed emails from the database (alternative route)
 */
router.get('/all', async (req, res) => {
  try {
    const emails = await getEmails();
    res.json(emails);
  } catch (error) {
    console.error('Error fetching emails:', error);
    res.status(500).json({ error: 'Failed to fetch emails' });
  }
});


module.exports = router;