# API Documentation

## Base URL

```
http://localhost:3000/api/ioc
```

## Authentication

All endpoints require valid API keys configured in the backend environment variables.

## Endpoints

### 1. Single IOC Analysis

**POST** `/analyze`

Analyze a single Indicator of Compromise (IOC) using multiple threat intelligence sources.

#### Request

```json
{
  "value": "google.com",
  "type": "domain",
  "description": "Optional description for the IOC"
}
```

#### Parameters

- `value` (string, required): The IOC value to analyze
- `type` (string, required): IOC type (`hash`, `url`, `ip`, `domain`)
- `description` (string, optional): Human-readable description

#### Response

```json
{
  "success": true,
  "data": {
    "ioc": {
      "value": "google.com",
      "type": "domain",
      "description": "Optional description for the IOC"
    },
    "analysis": {
      "verdict": "clean",
      "confidence": 95,
      "providers": {
        "virustotal": {
          "verdict": "clean",
          "detections": 0,
          "totalScans": 85,
          "metadata": {
            "reputation": 1,
            "last_analysis_date": "2024-01-15T10:30:00Z"
          }
        },
        "abuseipdb": {
          "verdict": "clean",
          "confidence": 0,
          "metadata": {
            "abuseConfidencePercentage": 0,
            "isWhitelisted": true,
            "countryCode": "US"
          }
        }
      },
      "categories": [],
      "analysisDate": "2024-01-15T10:30:00Z"
    }
  }
}
```

### 2. Bulk IOC Analysis

**POST** `/analyze/bulk`

Analyze multiple IOCs in a single request.

#### Request

```json
{
  "iocs": [
    {
      "value": "google.com",
      "type": "domain",
      "description": "Google domain"
    },
    {
      "value": "8.8.8.8",
      "type": "ip",
      "description": "Google DNS"
    }
  ]
}
```

#### Parameters

- `iocs` (array, required): Array of IOC objects (max 100 per request)

#### Response

```json
{
  "success": true,
  "data": {
    "results": [
      {
        "ioc": {
          "value": "google.com",
          "type": "domain"
        },
        "analysis": {
          "verdict": "clean",
          "confidence": 95,
          "providers": {
            "virustotal": { "verdict": "clean", "detections": 0 }
          }
        }
      }
    ],
    "summary": {
      "total": 2,
      "processed": 2,
      "failed": 0,
      "clean": 2,
      "suspicious": 0,
      "malicious": 0
    }
  }
}
```

### 3. File Analysis

**POST** `/file/analyze`

Upload a file to extract its hash and analyze reputation.

#### Request

```
Content-Type: multipart/form-data

file: <binary file data>
description: "Optional file description"
```

#### Parameters

- `file` (file, required): Binary file to analyze (max 100MB)
- `description` (string, optional): File description

#### Response

```json
{
  "success": true,
  "data": {
    "file": {
      "filename": "document.pdf",
      "size": 1024576,
      "mimetype": "application/pdf",
      "hashes": {
        "md5": "5d41402abc4b2a76b9719d911017c592",
        "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
        "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
      }
    },
    "analysis": {
      "verdict": "unknown",
      "confidence": 0,
      "providers": {
        "virustotal": {
          "verdict": "unknown",
          "detections": 0,
          "totalScans": 0
        }
      }
    }
  }
}
```

### 4. Bulk File Upload

**POST** `/file/bulk-upload`

Upload a CSV or Excel file containing multiple IOCs for bulk analysis.

#### Request

```
Content-Type: multipart/form-data

file: <CSV or Excel file>
```

#### CSV Format

```csv
ioc,type,description
google.com,domain,Sample domain
8.8.8.8,ip,Google DNS
https://example.com,url,Sample URL
```

#### Response

```json
{
  "success": true,
  "data": {
    "results": [
      {
        "ioc": {
          "value": "google.com",
          "type": "domain"
        },
        "analysis": {
          "verdict": "clean",
          "confidence": 95
        }
      }
    ],
    "summary": {
      "total": 100,
      "processed": 100,
      "failed": 0,
      "clean": 85,
      "suspicious": 10,
      "malicious": 5
    }
  }
}
```

### 5. IOC Type Detection

**GET** `/detect-type`

Automatically detect the type of an IOC value.

#### Parameters

- `value` (string, required): The IOC value to analyze

#### Example

```
GET /detect-type?value=google.com
```

#### Response

```json
{
  "success": true,
  "data": {
    "value": "google.com",
    "detectedType": "domain",
    "confidence": 100
  }
}
```

### 6. Health Check

**GET** `/health`

Check the health status of the API and external providers.

#### Response

```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "timestamp": "2024-01-15T10:30:00Z",
    "providers": {
      "virustotal": {
        "status": "available",
        "configured": true,
        "rateLimit": {
          "remaining": 3,
          "resetTime": "2024-01-15T10:31:00Z"
        }
      },
      "abuseipdb": {
        "status": "available",
        "configured": true
      },
      "urlscan": {
        "status": "available",
        "configured": false
      }
    }
  }
}
```

### 7. Sample CSV Download

**GET** `/sample-csv`

Download a sample CSV template for bulk IOC uploads.

#### Response

```
Content-Type: text/csv
Content-Disposition: attachment; filename="ioc-template.csv"

ioc,type,description
google.com,domain,Sample domain
8.8.8.8,ip,Sample IP address
https://example.com,url,Sample URL
5d41402abc4b2a76b9719d911017c592,hash,Sample MD5 hash
```

## Error Responses

### Validation Errors

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid IOC format",
    "details": {
      "field": "value",
      "reason": "Invalid domain format"
    }
  }
}
```

### Rate Limit Errors

```json
{
  "success": false,
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "API rate limit exceeded",
    "details": {
      "provider": "virustotal",
      "resetTime": "2024-01-15T10:31:00Z"
    }
  }
}
```

### API Key Errors

```json
{
  "success": false,
  "error": {
    "code": "API_KEY_ERROR",
    "message": "Invalid or missing API key",
    "details": {
      "provider": "virustotal"
    }
  }
}
```

## Rate Limits

### VirusTotal

- **Free Tier**: 4 requests/minute, 500 requests/day
- **Premium**: Higher limits based on subscription

### AbuseIPDB

- **Free Tier**: 1,000 requests/day
- **Premium**: Higher limits based on subscription

### URLScan.io

- **Free Tier**: 100 requests/hour
- **Premium**: Higher limits based on subscription

## Data Models

### IOC Object

```typescript
interface IOC {
  value: string;
  type: "hash" | "url" | "ip" | "domain";
  description?: string;
}
```

### Analysis Result

```typescript
interface AnalysisResult {
  verdict: "clean" | "suspicious" | "malicious" | "unknown";
  confidence: number; // 0-100
  providers: {
    [provider: string]: ProviderResult;
  };
  categories: string[];
  analysisDate: string;
}
```

### Provider Result

```typescript
interface ProviderResult {
  verdict: "clean" | "suspicious" | "malicious" | "unknown";
  confidence?: number;
  detections?: number;
  totalScans?: number;
  metadata?: Record<string, any>;
  error?: string;
}
```

## Best Practices

### Request Optimization

1. **Batch Processing**: Use bulk endpoints for multiple IOCs
2. **Caching**: Results are cached for 1 hour to reduce API calls
3. **Type Detection**: Use auto-detection when IOC type is unknown

### Error Handling

1. **Retry Logic**: Implement exponential backoff for rate limits
2. **Fallback**: Handle provider failures gracefully
3. **Validation**: Validate IOC formats before submission

### Security

1. **Input Sanitization**: All inputs are validated and sanitized
2. **Rate Limiting**: Built-in rate limiting protects against abuse
3. **CORS**: Configured for security

## SDKs and Libraries

### JavaScript/TypeScript

```typescript
import axios from "axios";

const client = axios.create({
  baseURL: "http://localhost:3000/api/ioc",
  timeout: 30000,
});

// Analyze single IOC
const result = await client.post("/analyze", {
  value: "google.com",
  type: "domain",
});
```

### Python

```python
import requests

def analyze_ioc(value, type, description=None):
    url = 'http://localhost:3000/api/ioc/analyze'
    data = {
        'value': value,
        'type': type,
        'description': description
    }
    response = requests.post(url, json=data)
    return response.json()
```

### cURL

```bash
# Analyze single IOC
curl -X POST http://localhost:3000/api/ioc/analyze \
  -H "Content-Type: application/json" \
  -d '{"value": "google.com", "type": "domain"}'

# Upload file for analysis
curl -X POST http://localhost:3000/api/ioc/file/analyze \
  -H "Content-Type: multipart/form-data" \
  -F "file=@document.pdf" \
  -F "description=Sample document"
```
