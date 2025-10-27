# Email Database Management API

## Overview

This document details the database operations for managing processed emails in the phishing detection system. These endpoints allow retrieval and deletion of email records stored in PostgreSQL.

## Base URL

```
https://phishing-detection-api.kentharold.space/api/emails
```

## Endpoints

### GET /all

Retrieves all processed emails from the database with full analysis data. Supports flexible filtering to narrow down results.

#### Request

```
GET /api/emails/all
```

**Headers:**
- `Content-Type: application/json`

**Query Parameters:**
- `sender` (string): Filter by sender email (partial match, case-insensitive)
- `subject` (string): Filter by subject (partial match, case-insensitive)
- `sender_domain` (string): Filter by sender domain (exact match)
- `threat_level` (string or number): Filter by threat level based on phishing_score_cti ranges ("low": score < 0.4 or NULL, "medium": score >= 0.4 and < 0.7, "high": score >= 0.7, "critical": score >= 0.9, or specific numeric score)
- `cti_confidence` (string): Filter by CTI confidence ("low", "medium", "high")
- `start_date` (string): Filter from date (ISO 8601 format)
- `end_date` (string): Filter to date (ISO 8601 format)
- `has_attachments` (string): Filter by attachment presence ("true" or "false")

#### Filtering Examples

**Filter high-threat emails:**
```
GET /api/emails/all?threat_level=high
```

**Filter emails from specific domain:**
```
GET /api/emails/all?sender_domain=suspicious.com
```

**Filter emails with attachments in date range:**
```
GET /api/emails/all?has_attachments=true&start_date=2023-01-01&end_date=2023-12-31
```

**Filter by subject keyword:**
```
GET /api/emails/all?subject=password
```

#### Response

**Success Response (200):**
```json
[
  {
    "id": 1,
    "sender": "malicious@phishingsite.com",
    "recipient": "victim@company.com",
    "subject": "Urgent: Account Security Alert",
    "body": "Your account has been compromised. Click here to reset your password: http://phishingsite.com/reset",
    "attachments": ["invoice.pdf"],
    "attachment_hashes": ["a1b2c3d4e5f6..."],
    "timestamp": "2023-10-24T14:30:15.000Z",
    "headers": {
      "received": "from mail.phishingsite.com ([192.168.1.100]) by smtp.company.com",
      "authentication-results": "spf=fail; dkim=fail; dmarc=fail"
    },
    "extracted_urls": [
      "http://phishingsite.com/reset",
      "https://legitimate-bank.com/login"
    ],
    "sender_domain": "phishingsite.com",
    "sender_ip": "192.168.1.100",
    "sender_name": "Bank Security Team",
    "spf_result": "fail",
    "dkim_result": "fail",
    "dmarc_result": "fail",
    "phishing_score_cti": 0.85,
    "cti_flags": [
      "malicious_domain_vt",
      "malicious_sender_ip_vt",
      "malicious_url_domain_vt"
    ],
    "detailed_analysis": {
      "domains": {
        "phishingsite.com": {
          "identifier": "phishingsite.com",
          "type": "domain",
          "stats": {"malicious": 5, "suspicious": 2, "harmless": 60, "undetected": 10},
          "reputation_score": 8,
          "threat_level": "high",
          "confidence": "high",
          "malicious_engines": [
            {"engine": "Malwarebytes", "result": "malicious", "method": "blacklist"},
            {"engine": "Kaspersky", "result": "malicious", "method": "blacklist"}
          ],
          "suspicious_engines": [
            {"engine": "SomeEngine", "result": "suspicious", "method": "heuristic"}
          ],
          "categories": ["phishing", "malware"],
          "tags": ["suspicious", "malicious"],
          "last_analysis_date": "2023-10-24T14:25:00Z",
          "popularity_ranks": {"Alexa": {"rank": 1000000}}
        },
        "legitimate-bank.com": {
          "identifier": "legitimate-bank.com",
          "type": "domain",
          "stats": {"malicious": 0, "suspicious": 0, "harmless": 85, "undetected": 7},
          "reputation_score": 95,
          "threat_level": "clean",
          "confidence": "high",
          "malicious_engines": [],
          "suspicious_engines": [],
          "categories": ["business", "finance"],
          "tags": [],
          "last_analysis_date": "2023-10-24T14:25:00Z",
          "popularity_ranks": {"Alexa": {"rank": 1000}}
        }
      },
      "ips": {
        "192.168.1.100": {
          "identifier": "192.168.1.100",
          "type": "ip",
          "stats": {"malicious": 3, "suspicious": 1, "harmless": 70, "undetected": 15},
          "reputation_score": 5,
          "threat_level": "high",
          "confidence": "medium",
          "malicious_engines": [
            {"engine": "AbuseIPDB", "result": "malicious", "method": "blacklist"}
          ],
          "suspicious_engines": [
            {"engine": "SomeEngine", "result": "suspicious", "method": "heuristic"}
          ],
          "categories": ["malware"],
          "tags": ["botnet"],
          "last_analysis_date": "2023-10-24T14:25:00Z",
          "popularity_ranks": {}
        }
      },
      "urls": {},
      "summary": {
        "total_checks": 3,
        "malicious_detections": 2,
        "suspicious_detections": 1,
        "reputation_score": 36,
        "confidence_level": "high"
      }
    },
    "threat_summary": {
      "overall_risk": "high",
      "confidence": "high",
      "total_analyzed": 3,
      "malicious_found": 2,
      "suspicious_found": 1,
      "average_reputation": 36
    }
  },
  {
    "id": 2,
    "sender": "newsletter@trusted-source.org",
    "recipient": "user@company.com",
    "subject": "Weekly Security Updates",
    "body": "Here are this week's security best practices...",
    "attachments": [],
    "attachment_hashes": [],
    "timestamp": "2023-10-24T09:15:22.000Z",
    "headers": {
      "received": "from mail.trusted-source.org ([10.0.0.50]) by smtp.company.com",
      "authentication-results": "spf=pass; dkim=pass; dmarc=pass"
    },
    "extracted_urls": [
      "https://trusted-source.org/best-practices"
    ],
    "sender_domain": "trusted-source.org",
    "sender_ip": "10.0.0.50",
    "sender_name": "Security Newsletter",
    "spf_result": "pass",
    "dkim_result": "pass",
    "dmarc_result": "pass",
    "phishing_score_cti": 0.05,
    "cti_flags": [
      "clean_domain_vt"
    ],
    "detailed_analysis": {
      "domains": {
        "trusted-source.org": {
          "threat_level": "clean",
          "reputation_score": 98,
          "malicious_engines": [],
          "total_engines": 92,
          "last_analysis": "2023-10-24T09:10:00Z"
        }
      },
      "ips": {
        "10.0.0.50": {
          "threat_level": "clean",
          "reputation_score": 100,
          "malicious_engines": [],
          "total_engines": 85,
          "last_analysis": "2023-10-24T09:10:00Z"
        }
      },
      "urls": {},
      "summary": {
        "total_checks": 2,
        "malicious_detections": 0,
        "suspicious_detections": 0,
        "reputation_score": 99,
        "confidence_level": "high"
      }
    },
    "threat_summary": {
      "overall_risk": "low",
      "confidence": "high",
      "total_analyzed": 2,
      "malicious_found": 0,
      "suspicious_found": 0,
      "average_reputation": 99
    }
  }
]
```

**Response Fields:**

- `id`: Unique database identifier (integer)
- All fields from the POST /emails response plus the database ID

**Empty Response (200):**
```json
[]
```

**Error Response (500):**
```json
{
  "error": "Failed to fetch emails"
}
```

#### Performance Notes

- Returns all emails in the database
- Response size can be large for many emails
- Consider pagination for production use
- Includes full CTI analysis data for each email

---

### DELETE /:id

Deletes a single email record by its database ID.

#### Request

```
DELETE /api/emails/123
```

**Path Parameters:**
- `id` (integer, required): The unique ID of the email to delete

**Headers:**
- `Content-Type: application/json`

#### Response

**Success Response (200):**
```json
{
  "message": "Email deleted successfully"
}
```

**Error Responses:**

**Invalid ID Format (400):**
```json
{
  "error": "Invalid ID"
}
```

**Email Not Found (404):**
```json
{
  "error": "Email not found"
}
```

**Server Error (500):**
```json
{
  "error": "Failed to delete email"
}
```

#### Example Usage

```bash
# Delete email with ID 5
curl -X DELETE http://localhost:3000/api/emails/5
```

```javascript
// Delete email with ID 5
fetch('/api/emails/5', {
  method: 'DELETE'
})
.then(response => response.json())
.then(data => console.log(data.message));
```

---

### DELETE /bulk

Deletes multiple email records in a single request.

#### Request

```
DELETE /api/emails/bulk
Content-Type: application/json

{
  "ids": [1, 3, 7, 12]
}
```

**Body Parameters:**
- `ids` (array of integers, required): Array of email IDs to delete
  - Must be non-empty array
  - Each ID must be a valid integer

**Headers:**
- `Content-Type: application/json`

#### Response

**Success Response (200):**
```json
{
  "message": "Emails deleted successfully",
  "deletedIds": [1, 3, 7, 12]
}
```

**Response Fields:**
- `message`: Success confirmation
- `deletedIds`: Array of IDs that were successfully deleted (matches input array if all successful)

**Error Responses:**

**Invalid Request Format (400):**
```json
{
  "error": "IDs must be a non-empty array"
}
```

**Server Error (500):**
```json
{
  "error": "Failed to delete emails"
}
```

#### Behavior Notes

- **Atomic Operation**: Either all specified emails are deleted, or none are (transaction-based)
- **Partial Success**: If some IDs don't exist, the operation fails entirely
- **Validation**: All IDs must exist in the database for the operation to succeed
- **Performance**: Optimized for bulk operations using single database transaction

#### Example Usage

```bash
# Delete multiple emails
curl -X DELETE http://localhost:3000/api/emails/bulk \
  -H "Content-Type: application/json" \
  -d '{"ids": [1, 3, 7]}'
```

```javascript
// Delete multiple emails
const emailsToDelete = [1, 3, 7, 12];

fetch('/api/emails/bulk', {
  method: 'DELETE',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    ids: emailsToDelete
  })
})
.then(response => response.json())
.then(data => {
  console.log(data.message);
  console.log('Deleted IDs:', data.deletedIds);
});
```

```python
import requests

# Delete multiple emails
emails_to_delete = [1, 3, 7, 12]

response = requests.delete('http://localhost:3000/api/emails/bulk',
                          json={'ids': emails_to_delete})
result = response.json()

print(result['message'])
print('Deleted IDs:', result['deletedIds'])
```

## Integration Examples

### Frontend Dashboard

```javascript
// Load all emails for display
async function loadEmails() {
  try {
    const response = await fetch('/api/emails/all');
    const emails = await response.json();

    // Display emails with threat indicators
    emails.forEach(email => {
      const riskLevel = email.threat_summary.overall_risk;
      const confidence = email.threat_summary.confidence;

      displayEmail(email, riskLevel, confidence);
    });
  } catch (error) {
    console.error('Failed to load emails:', error);
  }
}

// Delete selected emails
async function deleteSelectedEmails(selectedIds) {
  try {
    const response = await fetch('/api/emails/bulk', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: selectedIds })
    });

    if (response.ok) {
      const result = await response.json();
      console.log('Deleted:', result.deletedIds);
      // Refresh the email list
      loadEmails();
    }
  } catch (error) {
    console.error('Failed to delete emails:', error);
  }
}
```

### Admin Cleanup Script

```python
import requests

def cleanup_old_emails(threshold_days=30):
    """Delete emails older than threshold"""
    # First, get all emails
    response = requests.get('http://localhost:3000/api/emails/all')
    emails = response.json()

    # Filter old emails
    import datetime
    cutoff = datetime.datetime.now() - datetime.timedelta(days=threshold_days)

    old_email_ids = []
    for email in emails:
        email_date = datetime.datetime.fromisoformat(email['timestamp'].replace('Z', '+00:00'))
        if email_date < cutoff:
            old_email_ids.append(email['id'])

    if old_email_ids:
        # Bulk delete old emails
        delete_response = requests.delete('http://localhost:3000/api/emails/bulk',
                                        json={'ids': old_email_ids})
        print(f"Deleted {len(old_email_ids)} old emails")
    else:
        print("No old emails to delete")

cleanup_old_emails()
```

---

## Blocked Senders Management

### POST /block

Blocks a sender email address to prevent future emails from that sender.

#### Request

```
POST /api/emails/block
Content-Type: application/json

{
  "sender_email": "malicious@example.com",
  "reason": "High phishing score",
  "blocked_by": "admin"
}
```

**Body Parameters:**
- `sender_email` (string, required): Email address to block
- `reason` (string, optional): Reason for blocking (default: "Manual block")
- `blocked_by` (string, optional): Who blocked the sender (default: "system")

#### Response

**Success Response (200):**
```json
{
  "message": "Sender blocked successfully",
  "id": 1
}
```

**Already Blocked Response (200):**
```json
{
  "message": "Sender was already blocked"
}
```

### GET /blocked

Retrieves all blocked sender email addresses.

#### Request

```
GET /api/emails/blocked
```

#### Response

**Success Response (200):**
```json
[
  {
    "id": 1,
    "sender_email": "malicious@example.com",
    "reason": "High phishing score",
    "blocked_by": "admin",
    "blocked_at": "2023-10-25T10:00:00.000Z"
  },
  {
    "id": 2,
    "sender_email": "spam@domain.com",
    "reason": "Spam complaints",
    "blocked_by": "system",
    "blocked_at": "2023-10-25T09:30:00.000Z"
  }
]
```

### GET /blocked/:email

Checks if a specific sender email address is blocked.

#### Request

```
GET /api/emails/blocked/malicious@example.com
```

#### Response

**Success Response (200):**
```json
{
  "email": "malicious@example.com",
  "is_blocked": true
}
```

### DELETE /blocked/:email

Unblocks a previously blocked sender email address.

#### Request

```
DELETE /api/emails/blocked/malicious@example.com
```

#### Response

**Success Response (200):**
```json
{
  "message": "Sender unblocked successfully"
}
```

---

## Error Handling

### Common Error Scenarios

1. **Database Connection Issues**: Returns 500 with generic error message
2. **Invalid ID Format**: DELETE /:id returns 400 for non-numeric IDs
3. **Email Not Found**: DELETE /:id returns 404 for non-existent IDs
4. **Empty Bulk Array**: DELETE /bulk returns 400 for empty or invalid arrays
5. **Partial Bulk Failure**: DELETE /bulk fails entirely if any ID doesn't exist

### Best Practices

- **Check Response Status**: Always verify HTTP status codes
- **Handle Arrays Carefully**: Ensure IDs are integers in bulk operations
- **Implement Retry Logic**: For transient database errors
- **Validate Before Delete**: Consider fetching emails first to confirm existence
- **Use Transactions**: Bulk operations are atomic - partial failure isn't possible

## Security Considerations

- **Access Control**: Consider adding authentication for production use
- **Rate Limiting**: Implement rate limits to prevent abuse
- **Input Validation**: Validate all input parameters
- **Audit Logging**: Log all delete operations for compliance
- **Soft Deletes**: Consider implementing soft deletes for recovery options