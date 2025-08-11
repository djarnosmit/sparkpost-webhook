const crypto = require('crypto');
const { validateSparkPostEvent } = require('../lib/validation');
const { processEvents } = require('../lib/eventProcessor');
const { logger } = require('../lib/logger');
const { authenticateRequest } = require('../lib/auth');

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

// Webhook handler for Vercel serverless function
module.exports = async (req, res) => {
  const startTime = Date.now();
  
  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

  // Only allow POST requests
  if (req.method !== 'POST') {
    logger.warn(`Method not allowed: ${req.method}`, {
      method: req.method,
      url: req.url,
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.headers['user-agent']
    });
    return res.status(405).json({ 
      error: 'Method not allowed',
      message: 'Only POST requests are supported'
    });
  }

  try {
    // Log the incoming webhook request with full details
    const eventCount = Array.isArray(req.body) ? req.body.length : 0;
    const sampleEvent = eventCount > 0 ? req.body[0] : null;
    
    logger.logWebhookRequest(req, eventCount, sampleEvent);

    // Check if Elasticsearch is configured
    if (!elasticsearch) {
      logger.warn('Elasticsearch not configured - webhook cannot process events', {
        environment: process.env.NODE_ENV,
        hasCloudId: !!process.env.ELASTICSEARCH_CLOUD_ID,
        hasApiKey: !!process.env.ELASTICSEARCH_API_KEY
      });
      return res.status(503).json({
        error: 'Service unavailable',
        message: 'Elasticsearch not configured'
      });
    }

    // Authenticate the request
    const authResult = await authenticateRequest(req);
    
    // Log authentication attempt with details
    logger.logAuthAttempt(req, process.env.SPARKPOST_AUTH_TYPE || 'none', authResult);
    
    if (!authResult.valid) {
      logger.error('Authentication failed', {
        reason: authResult.reason,
        error: authResult.error,
        authType: process.env.SPARKPOST_AUTH_TYPE,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.headers['user-agent']
      });
      
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication failed',
        reason: authResult.reason
      });
    }

    // Log successful authentication
    logger.info('Request authenticated successfully', {
      authType: process.env.SPARKPOST_AUTH_TYPE,
      username: authResult.username,
      clientId: authResult.clientId,
      ip: req.ip || req.connection.remoteAddress
    });

    // Validate content type
    if (!req.headers['content-type']?.includes('application/json')) {
      logger.warn('Invalid content type', {
        contentType: req.headers['content-type'],
        ip: req.ip || req.connection.remoteAddress
      });
      return res.status(400).json({ 
        error: 'Invalid content type',
        message: 'Content-Type must be application/json'
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
    logger.debug('Starting event validation', {
      eventCount: events.length,
      bodySize: JSON.stringify(req.body).length,
      firstEventKeys: sampleEvent ? Object.keys(sampleEvent) : []
    });

    const { error: validationError, value: validatedData } = validateSparkPostEvent(events);
    
    if (validationError) {
      logger.logValidationError(validationError, {
        eventCount: events.length,
        sampleEvents: events.slice(0, 3), // Include first 3 events for debugging
        ip: req.ip || req.connection.remoteAddress
      });
      
      return res.status(400).json({ 
        error: 'Validation failed',
        message: validationError.message,
        details: validationError.details
      });
    }

    logger.info('Event validation successful', {
      validatedEventCount: validatedData.length,
      originalEventCount: events.length,
      processingTime: `${Date.now() - startTime}ms`
    });

    // Process events and send to Elasticsearch
    logger.debug('Starting Elasticsearch processing', {
      eventCount: validatedData.length,
      elasticsearchConfigured: !!elasticsearch
    });

    const result = await processEvents(validatedData, elasticsearch);

    const processingTime = Date.now() - startTime;
    
    logger.info('Webhook processing completed', {
      processed: result.processed,
      failed: result.failed,
      indexName: result.indexName,
      totalProcessingTime: `${processingTime}ms`,
      authType: process.env.SPARKPOST_AUTH_TYPE,
      ip: req.ip || req.connection.remoteAddress
    });

    // Return success response
    return res.status(200).json({
      success: true,
      message: 'Webhook processed successfully',
      processed: result.processed,
      failed: result.failed || 0,
      indexName: result.indexName,
      processingTime: `${processingTime}ms`,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    const processingTime = Date.now() - startTime;
    
    logger.logError(error, {
      method: req.method,
      url: req.url,
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.headers['user-agent'],
      contentType: req.headers['content-type'],
      eventCount: Array.isArray(req.body) ? req.body.length : 0,
      processingTime: `${processingTime}ms`,
      authType: process.env.SPARKPOST_AUTH_TYPE
    });
    
    // Don't expose internal errors to client
    const requestId = crypto.randomUUID();
    
    return res.status(500).json({
      error: 'Internal server error',
      message: 'Failed to process webhook',
      requestId,
      processingTime: `${processingTime}ms`
    });
  }
};