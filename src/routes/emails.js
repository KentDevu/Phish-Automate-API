const express = require('express');
const { parseEmail, getDomain, extractSenderIP } = require('../parser');
const { checkCTI } = require('../cti');
const { saveEmail, getEmails, deleteEmail, deleteEmails } = require('../db');

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


module.exports = router;