# SparkPost Webhook to Elasticsearch

A secure, production-ready webhook receiver that captures SparkPost email events and forwards them to Elasticsearch for analytics and monitoring.

## 🚀 Features

- ✅ **Secure webhook validation** with HMAC-SHA1 signature verification
- ✅ **Comprehensive data validation** using Joi schemas
- ✅ **Rate limiting** to prevent abuse
- ✅ **Elasticsearch integration** with proper indexing and mappings
- ✅ **Security headers** and best practices
- ✅ **Structured logging** with sensitive data sanitization
- ✅ **Health checks** for monitoring
- ✅ **Vercel-ready** serverless deployment
- ✅ **Event categorization** for better analytics
- ✅ **Geolocation support** with geo_point mapping

## 📋 Quick Start

### 1. Environment Setup

Create a `.env` file based on `.env.example`:

```bash
cp .env.example .env
```

Fill in your credentials:
```env
SPARKPOST_WEBHOOK_SECRET=your-sparkpost-webhook-secret-here
ELASTICSEARCH_CLOUD_ID=your-elasticsearch-cloud-id
ELASTICSEARCH_API_KEY=your-elasticsearch-api-key
NODE_ENV=production
LOG_LEVEL=info
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Local Development

```bash
# Install Vercel CLI if you haven't already
npm i -g vercel

# Start development server
npm run dev
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

**Headers:**
- `Content-Type: application/json`
- `X-SparkPost-Webhook-Signature: <hmac_signature>`

**Response:**
```json
{
  "success": true,
  "message": "Webhook processed successfully",
  "processed": 5,
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### GET /api/health

Health check endpoint for monitoring.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00.000Z",
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

1. In your SparkPost dashboard, go to **Webhooks**
2. Create a new webhook with your Vercel URL: `https://your-app.vercel.app/api/webhook`
3. Select the events you want to track:
   - **Core Events:** delivery, bounce, spam_complaint
   - **Engagement Events:** open, click, unsubscribe
   - **Sending Events:** injection, policy_rejection
4. Set authentication method and copy the webhook secret
5. Save and test the webhook

## 📊 Elasticsearch Integration

### Index Structure
Events are stored in daily indices: `sparkpost-events-YYYY-MM-DD`

### Event Categories
Events are automatically categorized:
- `engagement`: delivery, open, click, unsubscribe
- `sending`: injection, generation events
- `delivery_failure`: bounce, policy_rejection, out_of_band
- `delivery_issue`: delay
- `reputation`: spam_complaint
- `relay`: relay_* events

### Sample Queries

**Get recent bounces:**
```json
{
  "query": {
    "bool": {
      "must": [
        { "term": { "type": "bounce" } },
        { "range": { "@timestamp": { "gte": "now-1d" } } }
      ]
    }
  }
}
```

**Engagement analytics:**
```json
{
  "query": {
    "terms": { "type": ["open", "click", "delivery"] }
  },
  "aggs": {
    "by_type": {
      "terms": { "field": "type" }
    }
  }
}
```

## 🔒 Security Features

### Webhook Security
- HMAC-SHA1 signature validation with timing-safe comparison
- Input sanitization and validation with Joi schemas
- Rate limiting (1000 requests per 15 minutes per IP)

### Application Security
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- Sensitive data redaction in logs
- Error handling without information leakage

## 📝 Monitoring and Logging

### Log Levels
- `error`: Critical errors requiring immediate attention
- `warn`: Warning conditions
- `info`: General information (default)
- `debug`: Detailed debugging information

### Health Monitoring
Use `/api/health` endpoint for:
- Uptime monitoring
- Elasticsearch cluster health checks
- Response time tracking

## 🧪 Development

### Run Tests
```bash
npm test
npm run test:watch
```

### Code Quality
```bash
npm run lint
npm run lint:fix
```

### Local Testing with ngrok
```bash
# Start your dev server
npm run dev

# In another terminal, expose your local server
ngrok http 3000

# Use the ngrok URL in SparkPost webhook configuration
```

## 🚀 Production Deployment

### Vercel Deployment
1. Connect your GitHub repository to Vercel
2. Set environment variables in Vercel dashboard
3. Deploy automatically on git push
4. Configure custom domain if needed

### Environment Variables in Vercel
```
SPARKPOST_WEBHOOK_SECRET=your_secret_here
ELASTICSEARCH_CLOUD_ID=your_cloud_id
ELASTICSEARCH_API_KEY=your_api_key
NODE_ENV=production
LOG_LEVEL=info
```

## 📊 Project Structure

```
├── api/
│   ├── webhook.js          # Main webhook handler
│   └── health.js           # Health check endpoint
├── lib/
│   ├── validation.js       # Security & data validation
│   ├── eventProcessor.js   # Elasticsearch integration
│   └── logger.js           # Centralized logging
├── package.json            # Dependencies & scripts
├── vercel.json            # Vercel configuration
└── README.md              # Documentation
```

## 🐛 Troubleshooting

### Common Issues

**Webhook not receiving events:**
- Check SparkPost webhook configuration
- Verify webhook URL is accessible
- Ensure webhook secret matches

**Elasticsearch connection issues:**
- Verify Cloud ID and API key
- Check API key permissions
- Review cluster health

**Signature validation failing:**
- Ensure webhook secret is correct
- Check Content-Type header
- Verify request body encoding

### Debug Mode
```bash
export LOG_LEVEL=debug
vercel dev
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes and add tests
4. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details.

---

**🎉 Your SparkPost webhook is ready for production!**

Next steps:
1. Deploy to Vercel
2. Configure SparkPost webhook URL
3. Monitor via `/api/health` endpoint
4. Analyze events in Elasticsearch