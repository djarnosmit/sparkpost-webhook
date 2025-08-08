const crypto = require('crypto');
const Joi = require('joi');
const { logger } = require('./logger');

// SparkPost webhook signature validation (kept for potential future use)
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

// Schema for individual SparkPost event (after extraction from msys wrapper)
const sparkPostEventSchema = Joi.object({
  // Common required fields
  event_id: Joi.string().required(),
  timestamp: Joi.alternatives().try(
    Joi.string().isoDate(),
    Joi.string().pattern(/^\d+$/), // Unix timestamp as string
    Joi.number() // Unix timestamp as number
  ).required(),
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
  rcpt_to: Joi.string().email().optional(),
  recipient: Joi.string().email().optional(),
  recipient_domain: Joi.string().optional(),
  rcpt_type: Joi.string().optional(),
  rcpt_hash: Joi.string().optional(),
  raw_rcpt_to: Joi.string().optional(),

  // Message content
  subject: Joi.string().optional(),
  friendly_from: Joi.string().optional(),
  msg_from: Joi.string().email().optional(),
  msg_size: Joi.alternatives().try(Joi.number(), Joi.string()).optional(),

  // Tracking and metadata
  user_agent: Joi.string().optional(),
  ip_address: Joi.string().ip().optional(),
  sending_ip: Joi.string().ip().optional(),
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
  delv_method: Joi.string().optional(),
  raw_reason: Joi.string().optional(),
  queue_time: Joi.alternatives().try(Joi.number(), Joi.string()).optional(),
  num_retries: Joi.alternatives().try(Joi.number(), Joi.string()).optional(),

  // Metadata and custom fields
  rcpt_meta: Joi.object().optional(),
  rcpt_tags: Joi.array().items(Joi.string()).optional(),
  msg_meta: Joi.object().optional(),
  routing_domain: Joi.string().optional(),
  subaccount_id: Joi.string().optional(),

  // SparkPost specific fields
  ab_test_id: Joi.string().optional(),
  ab_test_version: Joi.string().optional(),
  amp_enabled: Joi.boolean().optional(),
  click_tracking: Joi.boolean().optional(),
  open_tracking: Joi.boolean().optional(),
  initial_pixel: Joi.boolean().optional(),
  injection_time: Joi.string().optional(),
  ip_pool: Joi.string().optional(),
  mailbox_provider: Joi.string().optional(),
  mailbox_provider_region: Joi.string().optional(),
  outbound_tls: Joi.string().optional(),
  recv_method: Joi.string().optional(),
  scheduled_time: Joi.alternatives().try(Joi.number(), Joi.string()).optional(),
  transactional: Joi.alternatives().try(Joi.boolean(), Joi.string()).optional(),
  device_token: Joi.string().optional(),

  // SMS specific fields
  sms_coding: Joi.string().optional(),
  sms_dst: Joi.string().optional(),
  sms_dst_npi: Joi.string().optional(),
  sms_dst_ton: Joi.string().optional(),
  sms_remoteids: Joi.array().items(Joi.string()).optional(),
  sms_segments: Joi.number().optional(),
  sms_src: Joi.string().optional(),
  sms_src_npi: Joi.string().optional(),
  sms_src_ton: Joi.string().optional()
}).unknown(true); // Allow additional fields for future compatibility

// Schema for SparkPost webhook batch (array of msys objects)
const sparkPostBatchSchema = Joi.array().items(
  Joi.object({
    msys: Joi.object({
      message_event: sparkPostEventSchema.optional(),
      track_event: sparkPostEventSchema.optional(),
      gen_event: sparkPostEventSchema.optional(),
      unsubscribe_event: sparkPostEventSchema.optional(),
      relay_event: sparkPostEventSchema.optional()
    }).or('message_event', 'track_event', 'gen_event', 'unsubscribe_event', 'relay_event')
  }).unknown(true)
).min(1).max(1000); // Limit batch size for security

// Extract and normalize SparkPost events from the msys wrapper
function extractSparkPostEvents(batchData) {
  const events = [];
  
  for (const item of batchData) {
    if (!item.msys) {
      logger.warn('Invalid SparkPost event structure - missing msys wrapper');
      continue;
    }

    // Find the event within the msys wrapper
    let event = null;
    let eventType = null;
    
    if (item.msys.message_event) {
      event = item.msys.message_event;
      eventType = 'message_event';
    } else if (item.msys.track_event) {
      event = item.msys.track_event;
      eventType = 'track_event';
    } else if (item.msys.gen_event) {
      event = item.msys.gen_event;
      eventType = 'gen_event';
    } else if (item.msys.unsubscribe_event) {
      event = item.msys.unsubscribe_event;
      eventType = 'unsubscribe_event';
    } else if (item.msys.relay_event) {
      event = item.msys.relay_event;
      eventType = 'relay_event';
    }

    if (event) {
      // Normalize timestamp format
      if (event.timestamp && typeof event.timestamp === 'string' && /^\d+$/.test(event.timestamp)) {
        // Convert Unix timestamp to ISO string
        event.timestamp = new Date(parseInt(event.timestamp) * 1000).toISOString();
      } else if (event.timestamp && typeof event.timestamp === 'number') {
        event.timestamp = new Date(event.timestamp * 1000).toISOString();
      }

      // Normalize recipient field (SparkPost uses rcpt_to, we use recipient)
      if (event.rcpt_to && !event.recipient) {
        event.recipient = event.rcpt_to;
      }

      // Add event source metadata
      event.sparkpost_event_type = eventType;
      
      events.push(event);
    } else {
      logger.warn('No recognized event type found in msys wrapper', { available_keys: Object.keys(item.msys) });
    }
  }

  return events;
}

// Validate SparkPost event batch
function validateSparkPostEvent(data) {
  // First validate the overall batch structure
  const { error: batchError } = sparkPostBatchSchema.validate(data, {
    abortEarly: false,
    stripUnknown: false,
    allowUnknown: true
  });

  if (batchError) {
    logger.warn('SparkPost batch validation failed:', batchError.details);
    return { error: batchError };
  }

  // Extract events from the msys wrapper
  const extractedEvents = extractSparkPostEvents(data);

  if (extractedEvents.length === 0) {
    const error = new Error('No valid events found in batch');
    logger.warn('No valid events extracted from SparkPost batch');
    return { error };
  }

  // Validate each extracted event
  for (const event of extractedEvents) {
    const { error: eventError } = sparkPostEventSchema.validate(event, {
      abortEarly: false,
      stripUnknown: false,
      allowUnknown: true
    });

    if (eventError) {
      logger.warn('Individual SparkPost event validation failed:', eventError.details);
      return { error: eventError };
    }
  }

  logger.info(`Successfully validated ${extractedEvents.length} SparkPost events`);
  return { value: extractedEvents };
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
  extractSparkPostEvents,
  rateLimitOptions,
  sanitizeInput
};