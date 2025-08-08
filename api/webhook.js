const crypto = require('crypto');
const { validateSparkPostEvent } = require('../lib/validation');
const { processEvents } = require('../lib/eventProcessor');
const { logger } = require('../lib/logger');

// Initialize Elasticsearch client only if credentials are provided
let elasticsearch = null;
if (process.env.ELASTICSEARCH_CLOUD_ID && process.env.ELASTICSEARCH_API_KEY) {
  const { Client } = require('@elastic/elasticsearch');
  elasticsearch = new Client({
    cloud: {
      id: process.env.ELASTICSEARCH_CLOUD_ID
    },
    auth: {
      apiKey: process.env.ELASTICSEARCH_API_KEY
    }
  });
}

// Validate SparkPost Basic Auth (if configured)
function validateBasicAuth(req) {
  const username = process.env.SPARKPOST_WEBHOOK_USERNAME;
  const password = process.env.SPARKPOST_WEBHOOK_PASSWORD;
  
  // Skip auth validation if not configured (for local testing)
  if (!username || !password) {
    logger.info('No Basic Auth configured - allowing request (development mode)');
    return true;
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    logger.warn('Missing or invalid Authorization header');
    return false;
  }

  try {
    const base64Credentials = authHeader.slice(6); // Remove 'Basic '
    const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
    const [reqUsername, reqPassword] = credentials.split(':');
    
    // Use timing-safe comparison to prevent timing attacks
    const usernameMatch = crypto.timingSafeEqual(
      Buffer.from(username),
      Buffer.from(reqUsername || '')
    );
    const passwordMatch = crypto.timingSafeEqual(
      Buffer.from(password),
      Buffer.from(reqPassword || '')
    );
    
    return usernameMatch && passwordMatch;
  } catch (error) {
    logger.error('Basic Auth validation error:', error);
    return false;
  }
}

// Webhook handler for Vercel serverless function
module.exports = async (req, res) => {
  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

  // Only allow POST requests
  if (req.method !== 'POST') {
    logger.warn(`Method not allowed: ${req.method}`);
    return res.status(405).json({ 
      error: 'Method not allowed',
      message: 'Only POST requests are supported'
    });
  }

  try {
    // Log incoming request for debugging
    logger.info('Webhook request received', {
      headers: {
        'content-type': req.headers['content-type'],
        'user-agent': req.headers['user-agent'],
        'content-length': req.headers['content-length']
      },
      bodyLength: Array.isArray(req.body) ? req.body.length : 'Not an array',
      bodyType: typeof req.body
    });

    // Check if Elasticsearch is configured
    if (!elasticsearch) {
      logger.warn('Elasticsearch not configured - webhook cannot process events');
      return res.status(503).json({
        error: 'Service unavailable',
        message: 'Elasticsearch not configured'
      });
    }

    // Validate Basic Authentication
    if (!validateBasicAuth(req)) {
      logger.error('Basic Auth validation failed');
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid credentials'
      });
    }

    // Validate content type
    if (!req.headers['content-type']?.includes('application/json')) {
      logger.warn('Invalid content type');
      return res.status(400).json({ 
        error: 'Invalid content type',
        message: 'Content-Type must be application/json'
      });
    }

    // Debug: Log first few events to understand the structure
    if (Array.isArray(req.body) && req.body.length > 0) {
      logger.info('Sample events received', {
        totalEvents: req.body.length,
        firstEvent: req.body[0],
        eventKeys: Object.keys(req.body[0] || {})
      });
    } else {
      logger.warn('Request body is not an array or is empty', {
        bodyType: typeof req.body,
        body: req.body
      });
    }

    // Handle empty request body gracefully
    if (!req.body || (Array.isArray(req.body) && req.body.length === 0)) {
      logger.info('Empty webhook request received - returning success');
      return res.status(200).json({
        success: true,
        message: 'Empty webhook processed successfully',
        processed: 0,
        timestamp: new Date().toISOString()
      });
    }

    // Filter out empty or invalid events before validation
    let events = Array.isArray(req.body) ? req.body : [req.body];
    events = events.filter(event => event && typeof event === 'object' && Object.keys(event).length > 0);
    
    if (events.length === 0) {
      logger.info('No valid events found after filtering');
      return res.status(200).json({
        success: true,
        message: 'No valid events to process',
        processed: 0,
        timestamp: new Date().toISOString()
      });
    }

    // Validate request body structure
    const { error: validationError, value: validatedData } = validateSparkPostEvent(events);
    if (validationError) {
      logger.error('Validation error details', {
        error: validationError.message,
        eventCount: events.length,
        sampleEvents: events.slice(0, 3) // Log first 3 events for debugging
      });
      
      return res.status(400).json({ 
        error: 'Validation failed',
        message: validationError.message,
        details: validationError.details
      });
    }

    // Process events and send to Elasticsearch
    const result = await processEvents(validatedData, elasticsearch);

    logger.info(`Successfully processed ${result.processed} events`);

    // Return success response
    return res.status(200).json({
      success: true,
      message: 'Webhook processed successfully',
      processed: result.processed,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Webhook processing error:', error);
    
    // Don't expose internal errors to client
    return res.status(500).json({
      error: 'Internal server error',
      message: 'Failed to process webhook',
      requestId: crypto.randomUUID()
    });
  }
};