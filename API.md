# Phishing Detection API Documentation

## Overview

This API provides comprehensive email analysis for phishing detection, integrating IMAP email parsing with VirusTotal threat intelligence. It processes raw email data and returns structured JSON with parsed content and CTI (Cyber Threat Intelligence) analysis.

## Base URL

```
https://phishing-detection-api.kentharold.space/api/emails
```

## Authentication

No authentication required for basic usage. VirusTotal API key is required for CTI analysis (set via `VT_API_KEY` environment variable).

## Endpoints

### POST /emails

#### POST /emails (n8n IMAP integration)

Use n8n's IMAP trigger or IMAP node to forward messages directly to this endpoint. The API accepts n8n HTTP Request format with a `body` wrapper and a `binary` object for attachments.

Recommended n8n flow:
1. IMAP Trigger / IMAP Email node -> emits message fields and binary attachments.
2. (Optional) Set or Function node to normalize fields into the expected shape.
3. HTTP Request node:
  - Method: POST
  - URL: https://phishing-detection-api.kentharold.space/api/emails
  - Headers: Content-Type: application/json
  - Enable "Send Binary Data"
  - Send Body: Raw JSON (use expressions to populate fields)

Example payload shape (use n8n expressions to inject values):

```json
{
  "body": {
   "rawEmail": {
    "headers": {{$json["headers"]}},
    "html": {{$json["html"]}},
    "text": {{$json["text"]}},
    "subject": "={{$json[\"subject\"]}}",
    "attachments": {{$json["attachments"] || []}}
   }
  },
  "binary": {
   "attachment1": {
    "data": "={{$binary[\"attachment_1\"].data}}",
    "fileName": "={{$binary[\"attachment_1\"].fileName}}",
    "mimeType": "={{$binary[\"attachment_1\"].mimeType}}"
   }
  }
}
```

Notes and tips:
- Use the IMAP Trigger to process incoming mail automatically or poll with the IMAP node for batches.
- If multiple attachments exist, include them under `binary` with unique keys (attachment1, attachment2, ...).
- If you prefer a simple JSON body, map `rawEmail` to a single string containing the full RFC822 message.
- Ensure "Send Binary Data" is enabled in the HTTP Request node so attachments are transmitted correctly.
- The API will parse the provided headers, text/html, and binary attachments to produce parsed email fields and CTI analysis.

#### Request Formats

The API accepts multiple input formats for flexibility:

1. **Raw Email String** (Content-Type: text/plain)
   ```json
   "Return-Path: <sender@example.com>\nReceived: from mail.example.com ([192.168.1.1])\nSubject: Test Email\n\nThis is the body."
   ```

2. **JSON with rawEmail field** (Content-Type: application/json)
   ```json
   {
     "rawEmail": "Return-Path: <sender@example.com>\n..."
   }
   ```

3. **Array of email objects** (for batch processing)
   ```json
   [
     {
       "rawEmail": "Return-Path: <sender1@example.com>\n..."
     },
     {
       "rawEmail": "Return-Path: <sender2@example.com>\n..."
     }
   ]
   ```

4. **n8n HTTP Request format** (with binary attachments)
   ```json
   {
     "body": {
       "rawEmail": {
         "headers": {...},
         "html": "...",
         "text": "...",
         "subject": "...",
         "attachments": [...]
       },
       "binary": {
         "attachment1": {
           "data": "base64data",
           "fileName": "file.pdf",
           "mimeType": "application/pdf"
         }
       }
     }
   }
   ```

#### Response

Returns a JSON object (or array for batch requests) containing parsed email data merged with CTI analysis.

**Success Response (200):**
```json
{
  "sender": "sender@example.com",
  "recipient": "recipient@domain.com",
  "subject": "Test Subject",
  "body": "Cleaned email body text",
  "attachments": ["attachment1.pdf", "attachment2.jpg"],
  "attachment_hashes": ["sha256hash1", "sha256hash2"],
  "timestamp": "2023-10-24T10:00:00.000Z",
  "headers": {
    "received": "...",
    "authentication-results": "..."
  },
  "extracted_urls": ["https://example.com", "http://suspicious.link"],
  "sender_domain": "example.com",
  "sender_ip": "192.168.1.1",
  "sender_name": "John Doe",
  "spf_result": "pass",
  "dkim_result": "pass",
  "dmarc_result": "pass",
  "phishing_score_cti": 0.8,
  "cti_flags": ["malicious_domain_vt", "suspicious_sender_ip_vt"],
  "detailed_analysis": {
    "domains": {
      "example.com": {
        "threat_level": "high",
        "reputation_score": 15,
        "malicious_engines": ["Engine1", "Engine2"],
        "total_engines": 90,
        "last_analysis": "2023-10-24T09:00:00Z"
      }
    },
    "ips": {
      "192.168.1.1": {
        "threat_level": "medium",
        "reputation_score": 45,
        "malicious_engines": ["Engine3"],
        "total_engines": 85,
        "last_analysis": "2023-10-24T09:00:00Z"
      }
    },
    "urls": {},
    "summary": {
      "total_checks": 2,
      "malicious_detections": 1,
      "suspicious_detections": 1,
      "reputation_score": 30,
      "confidence_level": "medium"
    }
  },
  "threat_summary": {
    "overall_risk": "high",
    "confidence": "medium",
    "total_analyzed": 2,
    "malicious_found": 1,
    "suspicious_found": 1,
    "average_reputation": 30
  }
}
```

**Error Response (400/500):**
```json
{
  "error": "Invalid request format. Send raw email string or JSON with rawEmail field(s)",
  "details": "Additional error details here"
}
```

#### Field Descriptions

- **Parsed Email Fields:**
  - `sender`: Sender email address
  - `recipient`: Recipient email address
  - `subject`: Email subject
  - `body`: Cleaned email body text
  - `attachments`: Array of attachment filenames
  - `attachment_hashes`: Array of SHA256 hashes for attachments
  - `timestamp`: Email timestamp (ISO format)
  - `headers`: Raw email headers object
  - `extracted_urls`: URLs found in email body
  - `sender_domain`: Domain extracted from sender email
  - `sender_ip`: IP address from email headers
  - `sender_name`: Sender display name
  - `spf_result`: SPF authentication result
  - `dkim_result`: DKIM authentication result
  - `dmarc_result`: DMARC authentication result

- **CTI Analysis Fields:**
  - `phishing_score_cti`: Overall phishing score (0.0-1.0)
  - `cti_flags`: Array of detected threat flags
  - `detailed_analysis`: Detailed VT analysis results
  - `threat_summary`: Summary of threat assessment

### GET /emails/all

Retrieves all processed emails from the database with optional filtering capabilities.

#### Request

```
GET /api/emails/all
```

**Query Parameters (all optional):**
- `sender` (string): Filter by sender email address (partial match, case-insensitive)
- `subject` (string): Filter by email subject (partial match, case-insensitive)
- `sender_domain` (string): Filter by sender domain (exact match)
- `threat_level` (string or number): Filter by threat level based on phishing_score_cti ranges ("low": score < 0.4 or NULL, "medium": score >= 0.4 and < 0.7, "high": score >= 0.7, "critical": score >= 0.9) or exact numeric score match (e.g., "0.5")
- `cti_confidence` (string): Filter by CTI confidence level (exact match). Possible values: "low", "medium", "high"
- `start_date` (string): Filter emails from this date onwards (ISO 8601 format, e.g., "2023-01-01" or "2023-01-01T00:00:00Z")
- `end_date` (string): Filter emails up to this date (ISO 8601 format)
- `has_attachments` (string): Filter by attachment presence ("true" for emails with attachments, "false" for emails without)

#### Examples

**Get all emails:**
```
GET /api/emails/all
```

**Filter by sender domain:**
```
GET /api/emails/all?sender_domain=gmail.com
```

**Filter by threat level:**
```
GET /api/emails/all?threat_level=high 
GET /api/emails/all?threat_level=0.7 

```

**Filter by date range:**
```
GET /api/emails/all?start_date=2023-01-01&end_date=2023-12-31
```

**Filter by subject keyword:**
```
GET /api/emails/all?subject=urgent
```

**Filter emails with attachments:**
```
GET /api/emails/all?has_attachments=true
```

**Combine multiple filters:**
```
GET /api/emails/all?threat_level=high&has_attachments=true&start_date=2023-01-01
```

#### Response

**Success Response (200):**
```json
[
  {
    "id": 1,
    "sender": "sender@example.com",
    "recipient": "recipient@example.com",
    "subject": "Test Email",
    "body": "Email body content...",
    "attachments": ["document.pdf", "attachment2.jpg"],
    "timestamp": "2023-01-01T12:00:00.000Z",
    "phishing_score_cti": 0.85,
    "cti_flags": ["suspicious_sender", "malicious_url"],
    "extracted_urls": ["http://malicious-site.com"],
    "sender_domain": "example.com",
    "sender_ip": "192.168.1.1",
    "sender_name": "John Doe",
    "spf_result": "pass",
    "dkim_result": "pass",
    "dmarc_result": "pass",
    "headers": {
      "return-path": "<sender@example.com>",
      "received": "from mail.example.com ([192.168.1.1])"
    },
    "attachment_hashes": ["sha256:abc123..."],
    "detailed_analysis": {
      "domains": {
        "example.com": {
          "identifier": "example.com",
          "type": "domain",
          "stats": {"malicious": 5, "suspicious": 2, "harmless": 60, "undetected": 10},
          "reputation_score": 85,
          "threat_level": "high",
          "confidence": "high",
          "malicious_engines": [{"engine": "Engine1", "result": "malicious"}],
          "suspicious_engines": [],
          "categories": ["phishing"],
          "tags": ["suspicious"],
          "last_analysis_date": "2023-10-24T09:00:00Z",
          "popularity_ranks": {}
        }
      },
      "ips": {},
      "urls": {},
      "summary": {
        "total_checks": 1,
        "malicious_detections": 1,
        "suspicious_detections": 0,
        "reputation_score": 85,
        "confidence_level": "high"
      }
    },
    "threat_summary": {
      "overall_risk": "high",
      "confidence": "high",
      "total_analyzed": 2,
      "malicious_found": 1,
      "suspicious_found": 1,
      "average_reputation": 30
    }
  }
]
```

**Error Response (500):**
```json
{
  "error": "Failed to fetch emails"
}
```

### DELETE /emails/:id

Deletes a single email by ID.

#### Request

```
DELETE /api/emails/123
```

**Path Parameters:**
- `id` (integer): Email ID to delete

#### Response

**Success Response (200):**
```json
{
  "message": "Email deleted successfully"
}
```

**Error Response (404):**
```json
{
  "error": "Email not found"
}
```

**Error Response (500):**
```json
{
  "error": "Failed to delete email"
}
```

### DELETE /emails/bulk

Deletes multiple emails by IDs.

#### Request

```
DELETE /api/emails/bulk
Content-Type: application/json

{
  "ids": [1, 2, 3]
}
```

**Body Parameters:**
- `ids` (array): Array of email IDs to delete

#### Response

**Success Response (200):**
```json
{
  "message": "Emails deleted successfully",
  "deletedIds": [1, 2, 3]
}
```

**Error Response (400):**
```json
{
  "error": "IDs must be a non-empty array"
}
```

**Error Response (500):**
```json
{
  "error": "Failed to delete emails"
}
```

## Threat Intelligence Integration

The API integrates with VirusTotal for comprehensive threat analysis:

- **Domain Analysis**: Checks sender domain reputation and threat level
- **IP Analysis**: Analyzes sender IP and DNS-resolved IPs
- **URL Analysis**: Scans URLs found in email body (currently disabled due to API limits)
- **Reputation Scoring**: 0-100 scale (lower is better)
- **Threat Levels**: clean/low/medium/high
- **Confidence Levels**: low/medium/high based on detection consistency

## Integration Examples

### JavaScript (Frontend)

```javascript
// Single email processing
const response = await fetch('/api/emails', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    rawEmail: rawEmailString
  })
});
const result = await response.json();

// Batch processing
const emails = [
  { rawEmail: email1 },
  { rawEmail: email2 }
];
const batchResponse = await fetch('/api/emails', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(emails)
});
const results = await batchResponse.json();
```

### Python

```python
import requests

# Process single email
response = requests.post('http://localhost:3000/api/emails',
                        json={'rawEmail': raw_email_string})
result = response.json()

# Check threat verdict
if result.get('threat_summary', {}).get('overall_risk') == 'high':
    print("MALICIOUS EMAIL DETECTED")
```

### n8n Integration

Use the HTTP Request node with:
- Method: POST
- URL: `http://localhost:3000/api/emails`
- Body: Pass email data in the supported format
- Use the response for workflow decisions based on `threat_summary.overall_risk`

## Error Handling

- **400 Bad Request**: Invalid input format
- **404 Not Found**: Email ID not found (DELETE operations)
- **500 Internal Server Error**: Processing or database errors

All error responses include an `error` field with details and a `details` field for additional context when available.

## Rate Limits

- VirusTotal API has rate limits (4 requests/minute for free tier)
- Consider implementing caching for repeated domain/IP checks
- Batch processing helps optimize API usage

## Security Notes

- Store VirusTotal API key securely in environment variables
- Validate input data to prevent injection attacks
- Consider implementing authentication for production use
- Monitor API usage to avoid hitting rate limits