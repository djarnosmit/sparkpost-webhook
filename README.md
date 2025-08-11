# SparkPost Webhook to Elasticsearch

A secure, production-ready webhook receiver that captures SparkPost email events and forwards them to Elasticsearch for analytics and monitoring.

## 🚀 Features

- ✅ **Flexible Authentication** - Basic Auth, OAuth 2.0, or none
- ✅ **Secure webhook validation** with comprehensive input sanitization
- ✅ **Enhanced debug logging** with HTTP headers and detailed request tracking
- ✅ **Comprehensive data validation** using Joi schemas
- ✅ **Rate limiting** to prevent abuse
- ✅ **Elasticsearch integration** with proper indexing and mappings
- ✅ **Security headers** and best practices
- ✅ **Structured logging** with sensitive data sanitization
- ✅ **Health checks** for monitoring
- ✅ **Vercel-ready** serverless deployment
- ✅ **Event categorization** for better analytics
- ✅ **Geolocation support** with geo_point mapping

## 🔐 Authentication

The webhook supports three authentication methods:

### **Basic Authentication**
```env
SPARKPOST_AUTH_TYPE=basic
SPARKPOST_WEBHOOK_USERNAME=your-username
SPARKPOST_WEBHOOK_PASSWORD=your-secure-password
```

### **OAuth 2.0 (JWT Bearer Tokens)**
```env
SPARKPOST_AUTH_TYPE=oauth
SPARKPOST_OAUTH_CLIENT_ID=your-oauth-client-id
SPARKPOST_OAUTH_JWKS_ENDPOINT=https://your-auth-provider.com/.well-known/jwks.json
SPARKPOST_OAUTH_AUDIENCE=your-audience
SPARKPOST_OAUTH_SCOPES=webhook:write,events:read
```

### **No Authentication (Development Only)**
```env
SPARKPOST_AUTH_TYPE=none
```

## 📋 Quick Start

### 1. Environment Setup

Create a `.env` file based on `.env.example`:

```bash
cp .env.example .env
```

Configure your authentication method and credentials:

```env
# Choose authentication type
SPARKPOST_AUTH_TYPE=basic  # or "oauth" or "none"

# Basic Auth (if using SPARKPOST_AUTH_TYPE=basic)
SPARKPOST_WEBHOOK_USERNAME=webhook-user
SPARKPOST_WEBHOOK_PASSWORD=secure-password-123

# OAuth (if using SPARKPOST_AUTH_TYPE=oauth)
SPARKPOST_OAUTH_CLIENT_ID=your-client-id
SPARKPOST_OAUTH_JWKS_ENDPOINT=https://auth.example.com/.well-known/jwks.json
SPARKPOST_OAUTH_AUDIENCE=sparkpost-webhook
SPARKPOST_OAUTH_SCOPES=webhook:write

# Elasticsearch Configuration
ELASTICSEARCH_CLOUD_ID=your-elasticsearch-cloud-id
ELASTICSEARCH_API_KEY=your-elasticsearch-api-key

# Debug Configuration
NODE_ENV=production
LOG_LEVEL=debug  # Use "debug" for detailed logging
LOG_HTTP_HEADERS=true  # Include HTTP headers in debug logs
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Local Development

```bash
# Start development server
vercel dev
```

The webhook will be available at `http://localhost:3000/api/webhook`

### 4. Deploy to Vercel

```bash
# Login to Vercel
vercel login

# Deploy
vercel --prod
```

**Set environment variables in Vercel dashboard:**
- Go to your project settings → Environment Variables
- Add all the variables from your `.env` file

## 📡 API Endpoints

### POST /api/webhook

Main webhook endpoint for receiving SparkPost events.

**Authentication Headers:**

For Basic Auth:
```
Authorization: Basic <base64(username:password)>
```

For OAuth:
```
Authorization: Bearer <jwt_token>
```

**Request:**
```bash
curl -X POST https://your-app.vercel.app/api/webhook \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n 'username:password' | base64)" \
  -d '[{
    "msys": {
      "message_event": {
        "event_id": "123456789",
        "timestamp": "2025-08-11T08:00:00.000Z",
        "type": "delivery",
        "recipient": "user@example.com"
      }
    }
  }]'
```

**Response:**
```json
{
  "success": true,
  "message": "Webhook processed successfully",
  "processed": 1,
  "failed": 0,
  "indexName": "sparkpost-events-2025-08-11",
  "processingTime": "45ms",
  "timestamp": "2025-08-11T08:00:00.000Z"
}
```

### GET /api/health

Health check endpoint for monitoring.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-08-11T08:00:00.000Z",
  "service": "sparkpost-webhook",
  "version": "1.0.0",
  "checks": {
    "elasticsearch": {
      "status": "healthy",
      "cluster_status": "green"
    }
  }
}
```

## 🔧 SparkPost Configuration

### **Basic Auth Setup**

1. In SparkPost dashboard → **Webhooks**
2. **Authentication Type:** Basic Auth
3. **Username/Password:** Use your configured credentials
4. **Target URL:** `https://your-app.vercel.app/api/webhook`

### **OAuth Setup**

1. **Authentication Type:** OAuth 2.0
2. **Target URL:** `https://your-app.vercel.app/api/webhook`
3. Configure your OAuth provider to issue JWT tokens with:
   - Proper audience (`SPARKPOST_OAUTH_AUDIENCE`)
   - Required scopes (`SPARKPOST_OAUTH_SCOPES`)
   - JWKS endpoint for verification

### **Development Setup**

1. **Authentication Type:** None
2. **Target URL:** `http://your-ngrok-url.ngrok.io/api/webhook`

## 🐛 Debug Logging

Enable comprehensive debug logging:

```env
LOG_LEVEL=debug
LOG_HTTP_HEADERS=true
```

**Debug logs include:**
- ✅ **HTTP Headers** - All incoming request headers (sanitized)
- ✅ **Authentication Details** - Auth type, success/failure, user info
- ✅ **Request Processing** - Processing times, event counts
- ✅ **SparkPost Headers** - Special SparkPost webhook headers
- ✅ **Validation Details** - Event validation results and errors
- ✅ **Elasticsearch Operations** - Index operations and results

**Sample debug output:**
```json
{
  "timestamp": "2025-08-11T08:00:00.000Z",
  "level": "DEBUG",
  "message": "Authentication attempt",
  "authType": "basic",
  "success": true,
  "username": "webhook-user",
  "ip": "192.168.1.100",
  "headers": {
    "authorization": "Basic [REDACTED]",
    "content-type": "application/json",
    "user-agent": "SparkPost"
  }
}
```

## 📊 Supported SparkPost Events

✅ **Message Events:** delivery, bounce, injection, spam_complaint, delay, policy_rejection  
✅ **Tracking Events:** open, initial_open, click, unsubscribe  
✅ **AMP Events:** amp_open, amp_click, amp_initial_open  
✅ **SMS Events:** sms_status  
✅ **Generation Events:** generation_failure, generation_rejection  
✅ **Relay Events:** All relay event types  

## 🔒 Security Features

### **Authentication Security**
- Timing-safe credential comparison
- JWT signature verification (OAuth)
- Configurable scopes and audiences
- Request IP logging and tracking

### **Application Security**
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- Input sanitization and validation
- Rate limiting (1000 req/15min)
- Sensitive data redaction in logs

### **Debug Security**
- Automatic credential redaction in logs
- Configurable header logging
- Safe error handling without information leakage

## 📈 Environment Variables Reference

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `SPARKPOST_AUTH_TYPE` | Authentication method: `basic`, `oauth`, or `none` | No | `none` |
| `SPARKPOST_WEBHOOK_USERNAME` | Basic Auth username | If auth=basic | - |
| `SPARKPOST_WEBHOOK_PASSWORD` | Basic Auth password | If auth=basic | - |
| `SPARKPOST_OAUTH_CLIENT_ID` | OAuth client ID | If auth=oauth | - |
| `SPARKPOST_OAUTH_JWKS_ENDPOINT` | JWKS endpoint URL | If auth=oauth | - |
| `SPARKPOST_OAUTH_AUDIENCE` | JWT audience claim | If auth=oauth | - |
| `SPARKPOST_OAUTH_SCOPES` | Required scopes (comma-separated) | No | - |
| `ELASTICSEARCH_CLOUD_ID` | Elasticsearch Cloud deployment ID | Yes | - |
| `ELASTICSEARCH_API_KEY` | Elasticsearch API key | Yes | - |
| `NODE_ENV` | Environment (development/production) | No | `development` |
| `LOG_LEVEL` | Logging level: `error`, `warn`, `info`, `debug` | No | `info` |
| `LOG_HTTP_HEADERS` | Include HTTP headers in debug logs | No | `false` |

## 🧪 Testing

### **Test Basic Auth**
```bash
curl -X POST http://localhost:3000/api/webhook \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n 'username:password' | base64)" \
  -d '[{"msys":{"message_event":{"event_id":"test","timestamp":"2025-08-11T08:00:00.000Z","type":"delivery","recipient":"test@example.com"}}}]'
```

### **Test OAuth**
```bash
curl -X POST http://localhost:3000/api/webhook \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '[{"msys":{"message_event":{"event_id":"test","timestamp":"2025-08-11T08:00:00.000Z","type":"delivery","recipient":"test@example.com"}}}]'
```

### **Test No Auth (Development)**
```bash
curl -X POST http://localhost:3000/api/webhook \
  -H "Content-Type: application/json" \
  -d '[{"msys":{"message_event":{"event_id":"test","timestamp":"2025-08-11T08:00:00.000Z","type":"delivery","recipient":"test@example.com"}}}]'
```

## 🚀 Production Deployment

Your enhanced webhook system now includes:

✅ **Flexible Authentication** - Choose the auth method that works for your setup  
✅ **Comprehensive Debug Logging** - Track every request with detailed logs  
✅ **Enhanced Security** - Multiple layers of protection and validation  
✅ **Production Ready** - Scalable, monitored, and reliable  

**🎉 Your SparkPost webhook is now enterprise-ready with flexible authentication and comprehensive debugging capabilities!**