const { simpleParser } = require('mailparser');
const crypto = require('crypto');

/**
 * Cleans the email body by removing MIME artifacts
 * @param {string} body - The raw body text
 * @returns {string} Cleaned body
 */
function cleanBody(body) {
  // Remove MIME boundaries
  body = body.replace(/--[^\r\n]*[\r\n]/g, '');
  // Remove Content-Type headers
  body = body.replace(/Content-Type:[^\r\n]*[\r\n]/g, '');
  // Remove charset info
  body = body.replace(/charset=[^\r\n]*[\r\n]/g, '');
  // Remove extra newlines
  body = body.replace(/[\r\n]+/g, '\n').trim();
  return body;
}

/**
 * Extracts domain from email address
 * @param {string} email
 * @returns {string|null}
 */
function getDomain(email) {
  // Extract email from <email> format
  const emailMatch = email.match(/<([^>]+)>/);
  const cleanEmail = emailMatch ? emailMatch[1] : email;
  // Extract domain from user@domain
  const domainMatch = cleanEmail.match(/@(.+)$/);
  return domainMatch ? domainMatch[1] : null;
}

/**
 * Extracts sender IP from email headers
 * @param {Object} headers
 * @returns {string|null}
 */
function extractSenderIP(headers) {
  if (!headers) return null;
  // First, try Received-SPF client-ip
  const receivedSpf = headers['received-spf'] || '';
  if (typeof receivedSpf === 'string') {
    const spfMatch = receivedSpf.match(/client-ip=(\d+\.\d+\.\d+\.\d+)/);
    if (spfMatch) return spfMatch[1];
  }
  // Then, try Received headers
  let received = headers.received;
  if (Array.isArray(received)) {
    // Get the last Received header, which is typically the originating one
    received = received[received.length - 1];
  }
  if (typeof received === 'string') {
    // Match all IPs in brackets and take the last one
    const ipMatches = received.match(/\[(\d+\.\d+\.\d+\.\d+)\]/g);
    return ipMatches ? ipMatches[ipMatches.length - 1].replace(/\[|\]/g, '') : null;
  }
  return null;
}

/**
 * Parses raw email data and extracts key fields
 * @param {string|Object} rawEmail - The raw email content or pre-parsed object
 * @returns {Promise<Object>} Parsed email object
 */
async function parseEmail(rawEmail) {
  try {
    let parsed;
    if (typeof rawEmail === 'string') {
      parsed = await simpleParser(rawEmail);
    } else {
      // Already parsed object (e.g., from n8n) - handle different formats
      if (rawEmail.rawEmail) {
        // n8n format with binary attachments
        console.log('Binary attachments:', rawEmail.rawEmail.binary);
        parsed = rawEmail.rawEmail;
        // Add attachments from binary
        parsed.attachments = parsed.attachments || [];
        if (parsed.binary) {
          Object.keys(parsed.binary).forEach(key => {
            const bin = parsed.binary[key];
            console.log('Processing binary key:', key, 'bin:', bin);
            if (bin && bin.data) {
              parsed.attachments.push({
                filename: bin.fileName || key,
                content: Buffer.from(bin.data, 'base64'),
                contentType: bin.mimeType || 'application/octet-stream'
              });
            }
          });
        }
        console.log('Final attachments:', parsed.attachments);
      } else if (rawEmail.json && rawEmail.json.rawEmail) {
        // Alternative n8n format
        console.log('Binary attachments:', rawEmail.binary);
        parsed = rawEmail.json.rawEmail;
        // Add attachments from binary
        parsed.attachments = parsed.attachments || [];
        if (rawEmail.binary) {
          Object.keys(rawEmail.binary).forEach(key => {
            const bin = rawEmail.binary[key];
            console.log('Processing binary key:', key, 'bin:', bin);
            if (bin && bin.data) {
              parsed.attachments.push({
                filename: bin.fileName || key,
                content: Buffer.from(bin.data, 'base64'),
                contentType: bin.mimeType || 'application/octet-stream'
              });
            }
          });
        }
        console.log('Final attachments:', parsed.attachments);
      } else if (rawEmail.headers && typeof rawEmail.headers === 'object' && !rawEmail.headers.get) {
        // n8n format: headers as plain object
        parsed = {
          headers: rawEmail.headers,
          html: rawEmail.html,
          text: rawEmail.text,
          subject: rawEmail.subject,
          date: rawEmail.date,
          to: rawEmail.to,
          from: rawEmail.from,
          messageId: rawEmail.messageId,
          attachments: rawEmail.attachments || []
        };
        // Handle binary attachments from n8n
        if (rawEmail.binary) {
          parsed.attachments = parsed.attachments || [];
          Object.keys(rawEmail.binary).forEach(key => {
            const bin = rawEmail.binary[key];
            console.log('Processing binary key:', key, 'bin:', bin);
            if (bin && bin.data) {
              parsed.attachments.push({
                filename: bin.fileName || key,
                content: Buffer.from(bin.data, 'base64'),
                contentType: bin.mimeType || 'application/octet-stream'
              });
            }
          });
        }
        console.log('Final attachments:', parsed.attachments);
      } else {
        // Standard mailparser format
        parsed = rawEmail;
      }
    }

    // Extract attachments filenames and hashes
    let attachments = [];
    let attachment_hashes = [];
    if (parsed.attachments) {
      parsed.attachments.forEach(att => {
        attachments.push(att.filename || att.name || 'unknown');
        if (att.content) {
          const hash = crypto.createHash('sha256').update(att.content).digest('hex');
          attachment_hashes.push(hash);
        }
      });
    }

    // Extract authentication results
    let spf_result = null;
    let dkim_result = null;
    let dmarc_result = null;
    if (parsed.headers && parsed.headers['authentication-results']) {
      const auth = parsed.headers['authentication-results'];
      const spfMatch = auth.match(/spf=(\w+)/i);
      spf_result = spfMatch ? spfMatch[1] : null;
      const dkimMatch = auth.match(/dkim=(\w+)/i);
      dkim_result = dkimMatch ? dkimMatch[1] : null;
      const dmarcMatch = auth.match(/dmarc=(\w+)/i) || auth.match(/dara=(\w+)/i);
      dmarc_result = dmarcMatch ? dmarcMatch[1] : null;
    }

    // Clean body text (remove HTML if present, or use text version)
    let body = parsed.text || '';
    if (parsed.html) {
      // Simple HTML to text conversion (basic)
      body = parsed.html.replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
    }

    // Clean MIME artifacts
    body = cleanBody(body);

    // Normalize timestamp
    const timestamp = parsed.date ? (typeof parsed.date === 'string' ? parsed.date : parsed.date.toISOString()) : new Date().toISOString();

    // Extract additional fields
    const urlRegex = /https?:\/\/[^>\s]+/g;
    const extractedUrls = body.match(urlRegex) || [];
    const senderDomain = parsed.from && parsed.from.text ? getDomain(parsed.from.text) : null;
    const senderIP = extractSenderIP(parsed.headers);
    const senderName = parsed.from && parsed.from.value && parsed.from.value[0] ? parsed.from.value[0].name : null;

    return {
      sender: parsed.from ? parsed.from.text : '',
      recipient: parsed.to ? parsed.to.text : '',
      subject: parsed.subject || '',
      body: body,
      attachments: attachments,
      attachment_hashes: attachment_hashes,
      timestamp: timestamp,
      headers: parsed.headers || {},
      extracted_urls: extractedUrls,
      sender_domain: senderDomain,
      sender_ip: senderIP,
      sender_name: senderName,
      spf_result: spf_result,
      dkim_result: dkim_result,
      dmarc_result: dmarc_result
    };
  } catch (error) {
    console.error('Error parsing email:', error);
    return {
      sender: '',
      recipient: '',
      subject: '',
      body: '',
      attachments: [],
      attachment_hashes: [],
      timestamp: new Date().toISOString(),
      headers: {},
      extracted_urls: [],
      sender_domain: null,
      sender_ip: null,
      sender_name: null,
      spf_result: null,
      dkim_result: null,
      dmarc_result: null
    };
  }
}

module.exports = { parseEmail, getDomain, extractSenderIP };