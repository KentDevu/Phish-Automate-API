const axios = require('axios');

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
 * Extracts domain from URL
 * @param {string} url
 * @returns {string|null}
 */
function extractDomainFromUrl(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname;
  } catch {
    return null;
  }
}

/**
 * Extracts sender IP from email headers
 * @param {Object} headers
 * @returns {string|null}
 */
function extractSenderIP(headers) {
  if (!headers) return null;
  const received = headers.received || '';
  // Match IP in brackets, typically the sending IP
  const ipMatch = received.match(/\[(\d+\.\d+\.\d+\.\d+)\]/);
  return ipMatch ? ipMatch[1] : null;
}

/**
 * Mock CTI (Cyber Threat Intelligence) module with VirusTotal integration
 * @param {Object} emailData - The parsed email data
 * @returns {Promise<Object>} CTI results with score and flags
 */
async function checkCTI(emailData) {
  const flags = [];
  let score = 0.0;

  // Extract URLs from body for scanning
  const urlRegex = /https?:\/\/[^\s]+/g;
  let urls = emailData.body.match(urlRegex) || [];
  // Clean URLs by removing angle brackets
  urls = urls.map(url => url.replace(/[<>]/g, ''));

  const domain = getDomain(emailData.sender);

  // Check URLs with VirusTotal - DISABLED due to API issues
  const urlDomains = new Set();
  const urlIPs = new Set();
  for (const url of urls) {
    // Extract domain or IP from URL for further checks
    const hostname = extractDomainFromUrl(url);
    if (hostname) {
      const ipRegex = /^\d+\.\d+\.\d+\.\d+$/;
      if (ipRegex.test(hostname)) {
        urlIPs.add(hostname);
      } else {
        urlDomains.add(hostname);
      }
    }
  }

  // Sequential: After URLhaus, check domains from URLs with VT if different from sender domain
  for (const urlDomain of urlDomains) {
    if (urlDomain !== domain) {
      try {
        const urlDomainResponse = await axios.get(`https://www.virustotal.com/api/v3/domains/${urlDomain}`, {
          headers: { 'x-apikey': process.env.VT_API_KEY }
        });
        console.log('VT domain response for URL domain', urlDomain, ':', urlDomainResponse.data);
        const urlDomainStats = urlDomainResponse.data.data.attributes.last_analysis_stats;
        if (urlDomainStats.malicious > 0) {
          flags.push('malicious_url_domain_vt');
          score += 0.5;
        }
      } catch (error) {
        console.error('VT URL domain error for', urlDomain, ':', error.response ? error.response.data : error.message);
      }
    }
  }

  // VirusTotal domain check
  if (domain && process.env.VT_API_KEY) {
    try {
      const response = await axios.get(`https://www.virustotal.com/api/v3/domains/${domain}`, {
        headers: { 'x-apikey': process.env.VT_API_KEY }
      });
      console.log('VT domain response for', domain, ':', response.data);
      const stats = response.data.data.attributes.last_analysis_stats;
      console.log('Domain stats for', domain, ':', stats);
      if (stats.malicious > 0) {
          flags.push('malicious_domain_vt');
          score += 0.5;
          console.log('Added malicious_domain_vt, score now:', score);
        }      // Sequential: Extract IPs from VT domain response and check each with VT IP API
      const dnsRecords = response.data.data.attributes.last_dns_records || [];
      for (const record of dnsRecords) {
        if (record.type === 'A' && record.value) {
          try {
            const ipResponse = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${record.value}`, {
              headers: { 'x-apikey': process.env.VT_API_KEY }
            });
            console.log('VT IP response for', record.value, ':', ipResponse.data);
            const ipStats = ipResponse.data.data.attributes.last_analysis_stats;
            if (ipStats.malicious > 0) {
              flags.push('malicious_ip_vt');
              score += 0.4;
              console.log('Added malicious_ip_vt, score now:', score);
            }
          } catch (ipError) {
            console.error('VT IP error for', record.value, ':', ipError.response ? ipError.response.data : ipError.message);
          }
        }
      }

      // Sequential: Check sender IP if available and different from domain IPs
      const senderIP = extractSenderIP(emailData.headers);
      if (senderIP && !dnsRecords.some(record => record.value === senderIP)) {
        try {
          const senderIPResponse = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${senderIP}`, {
            headers: { 'x-apikey': process.env.VT_API_KEY }
          });
          console.log('VT IP response for sender IP', senderIP, ':', senderIPResponse.data);
          const senderIPStats = senderIPResponse.data.data.attributes.last_analysis_stats;
          if (senderIPStats.malicious > 0) {
            flags.push('malicious_sender_ip_vt');
            score += 0.4;
            console.log('Added malicious_sender_ip_vt, score now:', score);
          }
        } catch (error) {
          console.error('VT sender IP error for', senderIP, ':', error.response ? error.response.data : error.message);
        }
      }
    } catch (error) {
      console.error('VT domain error:', error.response ? error.response.data : error.message);
      // Fallback to mock if VT fails
      if (emailData.sender.toLowerCase().includes('phish') || emailData.sender.toLowerCase().includes('malicious')) {
        flags.push('malicious_domain');
        score += 0.4;
      }
    }
  } else {
    // No API key, use mock
    if (emailData.sender.toLowerCase().includes('phish') || emailData.sender.toLowerCase().includes('malicious')) {
      flags.push('malicious_domain');
      score += 0.4;
    }
  }

  // Check URL domains with VT
  for (const urlDomain of urlDomains) {
    if (urlDomain === domain) continue; // already checked
    if (process.env.VT_API_KEY) {
      try {
        const response = await axios.get(`https://www.virustotal.com/api/v3/domains/${urlDomain}`, {
          headers: { 'x-apikey': process.env.VT_API_KEY }
        });
        console.log('VT URL domain response for', urlDomain, ':', response.data);
        const stats = response.data.data.attributes.last_analysis_stats;
        console.log('URL domain stats for', urlDomain, ':', stats);
        if (stats.malicious > 0) {
          flags.push('malicious_url_domain_vt');
          score += 0.5;
          console.log('Added malicious_url_domain_vt, score now:', score);
        }
      } catch (error) {
        console.error('VT URL domain error for', urlDomain, ':', error.response ? error.response.data : error.message);
      }
    }
  }

  // Check URL IPs with VT
  for (const ip of urlIPs) {
    if (process.env.VT_API_KEY) {
      try {
        const ipResponse = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
          headers: { 'x-apikey': process.env.VT_API_KEY }
        });
        console.log('VT URL IP response for', ip, ':', ipResponse.data);
        const ipStats = ipResponse.data.data.attributes.last_analysis_stats;
        console.log('URL IP stats for', ip, ':', ipStats);
        if (ipStats.malicious > 0) {
          flags.push('malicious_url_ip_vt');
          score += 0.4;
          console.log('Added malicious_url_ip_vt, score now:', score);
        }
      } catch (ipError) {
        console.error('VT URL IP error for', ip, ':', ipError.response ? ipError.response.data : ipError.message);
      }
    }
  }

  // Cap score at 1.0
  score = Math.min(score, 1.0);

  return {
    phishing_score_cti: score,
    cti_flags: flags
  };
}

module.exports = { checkCTI };