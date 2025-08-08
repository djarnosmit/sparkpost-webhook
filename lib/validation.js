const crypto = require('crypto');
const Joi = require('joi');
const { logger } = require('./logger');

// SparkPost webhook signature validation
function validateSignature(payload, signature, secret) {
  if (!signature || !secret) {
    logger.warn('Missing signature or secret');
    return false;
  }

  try {
    // SparkPost uses HMAC-SHA1 for webhook signatures
    const expectedSignature = crypto
      .createHmac('sha1', secret)
      .update(payload, 'utf8')
      .digest('hex');

    // Use timing-safe comparison to prevent timing attacks
    return crypto.timingSafeEqual(
      Buffer.from(signature, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    );
  } catch (error) {
    logger.error('Signature validation error:', error);
    return false;
  }
}

// Joi schema for SparkPost event validation
const sparkPostEventSchema = Joi.array().items(
  Joi.object({
    // Common fields for all event types
    event_id: Joi.string().required(),
    timestamp: Joi.string().isoDate().required(),
    type: Joi.string().valid(
      'delivery',
      'injection',
      'bounce',
      'delay',
      'policy_rejection',
      'out_of_band',
      'open',
      'click',
      'generation_failure',
      'generation_rejection',
      'spam_complaint',
      'unsubscribe',
      'relay_injection',
      'relay_rejection',
      'relay_delivery',
      'relay_tempfail',
      'relay_permfail',
      'list_unsubscribe',
      'link_unsubscribe'
    ).required(),

    // Message identification
    message_id: Joi.string().optional(),
    transmission_id: Joi.string().optional(),
    campaign_id: Joi.string().optional(),
    customer_id: Joi.string().optional(),
    template_id: Joi.string().optional(),
    template_version: Joi.string().optional(),

    // Recipient information
    recipient: Joi.string().email().optional(),
    recipient_domain: Joi.string().optional(),
    recipient_type: Joi.string().optional(),

    // Message content
    subject: Joi.string().optional(),
    friendly_from: Joi.string().optional(),
    msg_from: Joi.string().email().optional(),
    msg_size: Joi.number().optional(),

    // Tracking and metadata
    user_agent: Joi.string().optional(),
    ip_address: Joi.string().ip().optional(),
    geo_ip: Joi.object({
      country: Joi.string().optional(),
      region: Joi.string().optional(),
      city: Joi.string().optional(),
      latitude: Joi.number().optional(),
      longitude: Joi.number().optional()
    }).optional(),

    // Event-specific data
    target_link_name: Joi.string().optional(),
    target_link_url: Joi.string().uri().optional(),
    bounce_class: Joi.number().optional(),
    reason: Joi.string().optional(),
    error_code: Joi.string().optional(),
    delivery_method: Joi.string().optional(),
    raw_reason: Joi.string().optional(),
    queue_time: Joi.string().optional(),

    // Metadata and custom fields
    rcpt_meta: Joi.object().optional(),
    rcpt_tags: Joi.array().items(Joi.string()).optional(),
    msg_meta: Joi.object().optional(),
    routing_domain: Joi.string().optional(),
    sending_ip: Joi.string().ip().optional(),
    subaccount_id: Joi.string().optional(),

    // Raw event data (for debugging)
    raw_event: Joi.object().optional()
  }).unknown(true) // Allow additional fields for future compatibility
).min(1).max(1000); // Limit batch size for security

// Validate SparkPost event data
function validateSparkPostEvent(data) {
  const { error, value } = sparkPostEventSchema.validate(data, {
    abortEarly: false,
    stripUnknown: false,
    allowUnknown: true
  });

  if (error) {
    logger.warn('SparkPost event validation failed:', error.details);
    return { error };
  }

  return { value };
}

// Rate limiting validation (to be used with express-rate-limit)
const rateLimitOptions = {
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // limit each IP to 1000 requests per windowMs
  message: {
    error: 'Too many requests',
    message: 'Rate limit exceeded. Please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip rate limiting for health checks
    return req.path === '/health' || req.path === '/api/health';
  }
};

// Input sanitization
function sanitizeInput(input) {
  if (typeof input !== 'string') {
    return input;
  }
  
  // Remove potentially harmful characters
  return input
    .replace(/[<>]/g, '') // Remove angle brackets
    .replace(/javascript:/gi, '') // Remove javascript: protocol
    .replace(/on\w+\s*=/gi, '') // Remove event handlers
    .trim();
}

module.exports = {
  validateSignature,
  validateSparkPostEvent,
  rateLimitOptions,
  sanitizeInput
};