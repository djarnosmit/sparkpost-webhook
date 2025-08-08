const crypto = require('crypto');
const { validateSparkPostEvent, validateSignature } = require('../lib/validation');
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
    // Check if Elasticsearch is configured
    if (!elasticsearch) {
      logger.warn('Elasticsearch not configured - webhook cannot process events');
      return res.status(503).json({
        error: 'Service unavailable',
        message: 'Elasticsearch not configured'
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

    // Get raw body for signature validation
    const rawBody = JSON.stringify(req.body);
    const signature = req.headers['x-sparkpost-webhook-signature'];

    // Skip signature validation in development if no secret is provided
    const webhookSecret = process.env.SPARKPOST_WEBHOOK_SECRET;
    if (webhookSecret && !validateSignature(rawBody, signature, webhookSecret)) {
      logger.error('Invalid webhook signature');
      return res.status(401).json({ 
        error: 'Unauthorized',
        message: 'Invalid webhook signature'
      });
    } else if (!webhookSecret) {
      logger.warn('No webhook secret configured - skipping signature validation (development mode)');
    }

    // Validate request body structure
    const { error: validationError, value: validatedData } = validateSparkPostEvent(req.body);
    if (validationError) {
      logger.warn(`Validation error: ${validationError.message}`);
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