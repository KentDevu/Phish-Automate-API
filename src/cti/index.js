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
 * Analyzes VirusTotal response and extracts detailed threat intelligence
 * @param {Object} vtResponse - VirusTotal API response
 * @param {string} type - Type of check ('domain', 'ip', 'url')
 * @param {string} identifier - The domain/IP/URL being checked
 * @returns {Object} Detailed analysis results
 */
function analyzeVTResponse(vtResponse, type, identifier) {
  const attributes = vtResponse.data.attributes;
  const stats = attributes.last_analysis_stats;
  const results = attributes.last_analysis_results || {};

  // Calculate reputation score (0-100, higher is better)
  const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
  const reputationScore = total > 0 ? ((stats.harmless + stats.undetected) / total) * 100 : 50;

  // Extract malicious engines
  const maliciousEngines = Object.entries(results)
    .filter(([engine, result]) => result.category === 'malicious')
    .map(([engine, result]) => ({
      engine,
      result: result.result,
      method: result.method
    }));

  // Extract suspicious engines
  const suspiciousEngines = Object.entries(results)
    .filter(([engine, result]) => result.category === 'suspicious')
    .map(([engine, result]) => ({
      engine,
      result: result.result,
      method: result.method
    }));

  // Determine threat level
  let threatLevel = 'clean';
  let confidence = 'low';
  if (stats.malicious >= 3) {
    threatLevel = 'high';
    confidence = 'high';
  } else if (stats.malicious >= 2) {
    threatLevel = 'medium';
    confidence = 'medium';
  } else if (stats.malicious >= 1) {
    threatLevel = 'low';
    confidence = 'low';
  } else if (stats.suspicious >= 2) {
    threatLevel = 'suspicious';
    confidence = 'low';
  }

  return {
    identifier,
    type,
    stats,
    reputation_score: Math.round(reputationScore),
    threat_level: threatLevel,
    confidence,
    malicious_engines: maliciousEngines,
    suspicious_engines: suspiciousEngines,
    categories: attributes.categories || [],
    tags: attributes.tags || [],
    last_analysis_date: attributes.last_analysis_date,
    popularity_ranks: attributes.popularity_ranks || {}
  };
}

/**
 * Enhanced CTI (Cyber Threat Intelligence) module with detailed VirusTotal integration
 * @param {Object} emailData - The parsed email data
 * @returns {Promise<Object>} Detailed CTI results with comprehensive threat intelligence
 */
async function checkCTI(emailData) {
  const flags = [];
  let score = 0.0;
  const detailedResults = {
    domains: {},
    ips: {},
    urls: {},
    summary: {
      total_checks: 0,
      malicious_detections: 0,
      suspicious_detections: 0,
      reputation_score: 0,
      confidence_level: 'low'
    }
  };

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
        // Be more conservative: require at least 2 malicious detections
        if (urlDomainStats.malicious >= 2) {
          flags.push('malicious_url_domain_vt');
          score += 0.5;
        } else if (urlDomainStats.malicious > 0) {
          console.log('URL domain', urlDomain, 'has', urlDomainStats.malicious, 'malicious detection(s) - below threshold');
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

      const domainAnalysis = analyzeVTResponse(response.data, 'domain', domain);
      detailedResults.domains[domain] = domainAnalysis;
      detailedResults.summary.total_checks++;

      console.log('Domain analysis for', domain, ':', domainAnalysis);

      // Update scoring based on detailed analysis
      if (domainAnalysis.threat_level === 'high') {
        flags.push('malicious_domain_vt');
        score += 0.6;
        detailedResults.summary.malicious_detections++;
      } else if (domainAnalysis.threat_level === 'medium') {
        flags.push('suspicious_domain_vt');
        score += 0.4;
        detailedResults.summary.suspicious_detections++;
      } else if (domainAnalysis.threat_level === 'low') {
        flags.push('low_threat_domain_vt');
        score += 0.2;
      }

      // Add reputation score to overall calculation
      detailedResults.summary.reputation_score += domainAnalysis.reputation_score;      // Sequential: Extract IPs from VT domain response and check each with VT IP API
      const dnsRecords = response.data.data.attributes.last_dns_records || [];
      for (const record of dnsRecords) {
        if (record.type === 'A' && record.value) {
          try {
            const ipResponse = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${record.value}`, {
              headers: { 'x-apikey': process.env.VT_API_KEY }
            });
            console.log('VT IP response for', record.value, ':', ipResponse.data);

            const ipAnalysis = analyzeVTResponse(ipResponse.data, 'ip', record.value);
            detailedResults.ips[record.value] = ipAnalysis;
            detailedResults.summary.total_checks++;

            console.log('DNS IP analysis for', record.value, ':', ipAnalysis);

            // Update scoring based on detailed analysis
            if (ipAnalysis.threat_level === 'high') {
              flags.push('malicious_dns_ip_vt');
              score += 0.4;
              detailedResults.summary.malicious_detections++;
            } else if (ipAnalysis.threat_level === 'medium') {
              flags.push('suspicious_dns_ip_vt');
              score += 0.2;
              detailedResults.summary.suspicious_detections++;
            }

            // Add reputation score to overall calculation
            detailedResults.summary.reputation_score += ipAnalysis.reputation_score;
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

          const ipAnalysis = analyzeVTResponse(senderIPResponse.data, 'ip', senderIP);
          detailedResults.ips[senderIP] = ipAnalysis;
          detailedResults.summary.total_checks++;

          console.log('Sender IP analysis for', senderIP, ':', ipAnalysis);

          // Update scoring based on detailed analysis
          if (ipAnalysis.threat_level === 'high') {
            flags.push('malicious_sender_ip_vt');
            score += 0.5;
            detailedResults.summary.malicious_detections++;
          } else if (ipAnalysis.threat_level === 'medium') {
            flags.push('suspicious_sender_ip_vt');
            score += 0.3;
            detailedResults.summary.suspicious_detections++;
          } else if (ipAnalysis.threat_level === 'low') {
            flags.push('low_threat_sender_ip_vt');
            score += 0.1;
          }

          // Add reputation score to overall calculation
          detailedResults.summary.reputation_score += ipAnalysis.reputation_score;
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
        // Be more conservative: require at least 2 malicious detections
        if (stats.malicious >= 2) {
          flags.push('malicious_url_domain_vt');
          score += 0.5;
          console.log('Added malicious_url_domain_vt, score now:', score);
        } else if (stats.malicious > 0) {
          console.log('URL domain', urlDomain, 'has', stats.malicious, 'malicious detection(s) - below threshold');
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

        const ipAnalysis = analyzeVTResponse(ipResponse.data, 'ip', ip);
        detailedResults.ips[ip] = ipAnalysis;
        detailedResults.summary.total_checks++;

        console.log('URL IP analysis for', ip, ':', ipAnalysis);

        // Update scoring based on detailed analysis
        if (ipAnalysis.threat_level === 'high') {
          flags.push('malicious_url_ip_vt');
          score += 0.4;
          detailedResults.summary.malicious_detections++;
        } else if (ipAnalysis.threat_level === 'medium') {
          flags.push('suspicious_url_ip_vt');
          score += 0.2;
          detailedResults.summary.suspicious_detections++;
        }

        // Add reputation score to overall calculation
        detailedResults.summary.reputation_score += ipAnalysis.reputation_score;
      } catch (ipError) {
        console.error('VT URL IP error for', ip, ':', ipError.response ? ipError.response.data : ipError.message);
      }
    }
  }

  // Calculate final summary metrics
  if (detailedResults.summary.total_checks > 0) {
    detailedResults.summary.reputation_score = Math.round(
      detailedResults.summary.reputation_score / detailedResults.summary.total_checks
    );
  }

  // Determine overall confidence level
  if (detailedResults.summary.malicious_detections >= 2) {
    detailedResults.summary.confidence_level = 'high';
  } else if (detailedResults.summary.malicious_detections >= 1 || detailedResults.summary.suspicious_detections >= 3) {
    detailedResults.summary.confidence_level = 'medium';
  } else if (detailedResults.summary.suspicious_detections >= 1) {
    detailedResults.summary.confidence_level = 'low';
  }

  // Cap score at 1.0
  score = Math.min(score, 1.0);

  return {
    phishing_score_cti: score,
    cti_flags: flags,
    detailed_analysis: detailedResults,
    threat_summary: {
      overall_risk: score >= 0.7 ? 'high' : score >= 0.4 ? 'medium' : 'low',
      confidence: detailedResults.summary.confidence_level,
      total_analyzed: detailedResults.summary.total_checks,
      malicious_found: detailedResults.summary.malicious_detections,
      suspicious_found: detailedResults.summary.suspicious_detections,
      average_reputation: detailedResults.summary.reputation_score
    }
  };
}

module.exports = { checkCTI };