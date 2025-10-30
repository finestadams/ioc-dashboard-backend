# IOC Reputation Dashboard

A comprehensive web-based Indicators of Compromise (IOC) analysis platform that enables security professionals to analyze the reputation of various IOCs using multiple threat intelligence sources.

![IOC Dashboard](https://img.shields.io/badge/Status-Production%20Ready-green)
![Next.js](https://img.shields.io/badge/Next.js-16.0.1-black)
![NestJS](https://img.shields.io/badge/NestJS-10.0.0-red)
![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue)

## 🚀 Features

### Core Functionality

- **Single IOC Analysis**: Analyze individual hashes, URLs, IP addresses, and domains
- **Bulk IOC Analysis**: Process up to 1,000 IOCs via CSV/Excel upload
- **File Upload Scanning**: Upload files to extract hashes and check reputation
- **Real-time Results**: Get instant reputation insights with confidence scoring

### Intelligence Sources

- **VirusTotal**: File, URL, IP, and domain reputation
- **AbuseIPDB**: IP address abuse reporting
- **URLScan.io**: URL and domain scanning

### Analytics & Visualization

- **Interactive Charts**: Verdict distribution, IOC categorization, confidence trends
- **Risk Assessment**: Automated threat categorization (Malware, Phishing, Ransomware, etc.)
- **Historical Analysis**: Track analysis history with detailed metadata

### Security Features

- **Input Validation**: Comprehensive IOC format validation
- **Rate Limiting**: API rate limit handling and request throttling
- **Caching System**: Intelligent caching to reduce API calls
- **CORS Protection**: Secure cross-origin resource sharing

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend       │    │  External APIs  │
│   (Next.js)     │◄──►│   (NestJS)      │◄──►│  VirusTotal     │
│                 │    │                 │    │  AbuseIPDB      │
│ • React UI      │    │ • API Routes    │    │  URLScan.io     │
│ • State Mgmt    │    │ • File Process  │    │                 │
│ • Charts        │    │ • Caching       │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📋 Prerequisites

- **Node.js**: Version 18.0 or higher
- **npm**: Version 8.0 or higher
- **API Keys** (Required for full functionality):
  - [VirusTotal API Key](https://www.virustotal.com/gui/my-apikey)
  - [AbuseIPDB API Key](https://www.abuseipdb.com/api)
  - [URLScan.io API Key](https://urlscan.io/user/apikey/) (Optional)

## ⚡ Quick Start

### 1. Clone the Repository

```bash
git clone <repository-url>
cd ioc-reputation-dashboard
```

### 2. Backend Setup

```bash
cd backend
npm install

# Configure environment variables
cp .env.example .env
# Edit .env with your API keys
```

### 3. Frontend Setup

```bash
cd ../frontend
npm install
```

### 4. Start Development Servers

**Backend** (Terminal 1):

```bash
cd backend
npm run start:dev
```

**Frontend** (Terminal 2):

```bash
cd frontend
npm run dev
```

### 5. Access the Dashboard

Open your browser and navigate to `http://localhost:3001`

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the backend directory:

```env
# Server Configuration
PORT=3000
NODE_ENV=development
FRONTEND_URL=http://localhost:3001

# API Keys
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
URLSCAN_API_KEY=your_urlscan_api_key_here

# Cache Configuration
CACHE_TTL=3600
```

### API Key Setup

#### VirusTotal

1. Visit [VirusTotal](https://www.virustotal.com/gui/my-apikey)
2. Sign up/Login to get your API key
3. Free tier: 4 requests/minute, 500 requests/day

#### AbuseIPDB

1. Visit [AbuseIPDB](https://www.abuseipdb.com/api)
2. Register for an account
3. Free tier: 1,000 requests/day

#### URLScan.io (Optional)

1. Visit [URLScan.io](https://urlscan.io/user/apikey/)
2. Create an account and generate API key
3. Free tier: 100 requests/hour

## 📊 API Documentation

### Base URL

```
http://localhost:3000/api/ioc
```

### Endpoints

#### 1. Analyze Single IOC

```http
POST /analyze
Content-Type: application/json

{
  "value": "google.com",
  "type": "domain",
  "description": "Sample domain analysis"
}
```

#### 2. Bulk IOC Analysis

```http
POST /analyze/bulk
Content-Type: application/json

{
  "iocs": [
    {"value": "google.com", "type": "domain"},
    {"value": "8.8.8.8", "type": "ip"}
  ]
}
```

#### 3. File Analysis

```http
POST /file/analyze
Content-Type: multipart/form-data

file: <binary file data>
description: "Optional file description"
```

#### 4. Bulk Upload (CSV/Excel)

```http
POST /file/bulk-upload
Content-Type: multipart/form-data

file: <CSV or Excel file>
```

#### 5. Auto-detect IOC Type

```http
GET /detect-type?value=google.com
```

#### 6. Health Check

```http
GET /health
```

#### 7. Download Sample CSV

```http
GET /sample-csv
```

## 📁 File Formats

### CSV Template

```csv
ioc,type,description
google.com,domain,Sample domain
8.8.8.8,ip,Google DNS
https://example.com,url,Sample URL
5d41402abc4b2a76b9719d911017c592,hash,MD5 hash
```

### Supported IOC Types

- **hash**: MD5, SHA1, SHA256 file hashes
- **url**: Web URLs (http/https)
- **ip**: IPv4 addresses
- **domain**: Domain names/hostnames
- **file**: Binary files for hash extraction

## 🎯 Usage Examples

### Single IOC Analysis

1. Navigate to the "Single IOC" tab
2. Enter an IOC value (e.g., `google.com`)
3. Select or auto-detect the IOC type
4. Click "Analyze IOC"
5. Review the results with verdict, confidence, and metadata

### Bulk Analysis

1. Go to the "Bulk Analysis" tab
2. Download the sample CSV template
3. Fill in your IOCs following the template format
4. Upload the file
5. Monitor the progress and review results

### File Upload

1. Access the "File Upload" tab
2. Drag and drop or select a file
3. Wait for hash extraction and reputation analysis
4. Copy file hashes for further investigation

## 🔍 Understanding Results

### Verdicts

- **🟢 Clean**: No malicious activity detected
- **🟡 Suspicious**: Potentially harmful, requires investigation
- **🔴 Malicious**: Confirmed malicious activity
- **⚪ Unknown**: Insufficient data for determination

### Categories

- **🦠 Malware**: Generic malicious software
- **🎣 Phishing**: Credential theft attempts
- **🔒 Ransomware**: File encryption malware
- **🤖 Botnet**: Botnet infrastructure
- **📡 C2 Server**: Command & control servers
- **📧 Spam**: Spam-related infrastructure

### Confidence Scoring

- **80-100%**: High confidence
- **60-79%**: Medium confidence
- **30-59%**: Low confidence
- **0-29%**: Very low confidence

## 🚨 Rate Limiting

The dashboard handles API rate limits automatically:

- **VirusTotal**: 4 requests/minute (free tier)
- **AbuseIPDB**: 1,000 requests/day (free tier)
- **URLScan.io**: 100 requests/hour (free tier)

Bulk analysis includes intelligent batching and delays to respect these limits.

## 🛡️ Security Considerations

### Input Validation

- All IOC inputs are validated for format and type
- File uploads are restricted by size (100MB) and type
- CSV/Excel files are limited to 1,000 IOCs

### API Security

- CORS configured for frontend-only access
- Request throttling implemented
- Input sanitization on all endpoints

### Data Privacy

- No IOC data is permanently stored
- Results are cached temporarily (1 hour)
- No logging of sensitive information

## 🐛 Troubleshooting

### Common Issues

#### "No API key configured" warnings

- Ensure API keys are set in the `.env` file
- Restart the backend server after adding keys

#### Rate limit errors

- Wait for the rate limit window to reset
- Consider upgrading API subscriptions for higher limits

#### File upload failures

- Check file size (max 100MB)
- Ensure file format is supported (CSV, XLS, XLSX)

#### CORS errors

- Verify FRONTEND_URL in backend `.env` matches your frontend URL
- Check that both servers are running

### Debug Mode

Enable verbose logging:

```env
NODE_ENV=development
```

## 🚀 Deployment

### Docker Deployment (Recommended)

1. Create `docker-compose.yml`:

```yaml
version: "3.8"
services:
  backend:
    build: ./backend
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY}
      - ABUSEIPDB_API_KEY=${ABUSEIPDB_API_KEY}
      - URLSCAN_API_KEY=${URLSCAN_API_KEY}

  frontend:
    build: ./frontend
    ports:
      - "3001:3000"
    environment:
      - NEXT_PUBLIC_API_URL=http://backend:3000
```

2. Deploy:

```bash
docker-compose up -d
```

### Manual Deployment

#### Backend

```bash
cd backend
npm run build
npm run start:prod
```

#### Frontend

```bash
cd frontend
npm run build
npm start
```

## 🧪 Testing

### Backend Tests

```bash
cd backend
npm test
npm run test:e2e
```

### Frontend Tests

```bash
cd frontend
npm test
```

## 📈 Performance Optimization

### Caching Strategy

- API responses cached for 1 hour
- Reduces external API calls
- Configurable cache TTL

### Request Batching

- Bulk operations processed in batches
- Configurable batch sizes
- Automatic retry on failures

### Rate Limit Handling

- Intelligent request spacing
- Queue management for bulk operations
- Provider-specific rate limit handling

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow TypeScript best practices
- Add tests for new features
- Update documentation
- Ensure ESLint passes

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:

- Create an issue on GitHub
- Check the troubleshooting section
- Review API provider documentation

## 🙏 Acknowledgments

- [VirusTotal](https://www.virustotal.com/) for comprehensive malware analysis
- [AbuseIPDB](https://www.abuseipdb.com/) for IP reputation data
- [URLScan.io](https://urlscan.io/) for URL analysis capabilities
- [Next.js](https://nextjs.org/) and [NestJS](https://nestjs.com/) teams for excellent frameworks

---

**⚠️ Disclaimer**: This tool is for educational and professional security purposes only. Always comply with API terms of service and applicable laws when analyzing IOCs.
