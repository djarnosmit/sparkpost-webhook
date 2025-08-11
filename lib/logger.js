// Simple, secure logger for production use
class Logger {
  constructor() {
    this.logLevel = process.env.LOG_LEVEL || 'info';
    this.logHttpHeaders = process.env.LOG_HTTP_HEADERS === 'true';
    this.levels = {
      error: 0,
      warn: 1,
      info: 2,
      debug: 3
    };
    this.currentLevel = this.levels[this.logLevel] || this.levels.info;
  }

  formatMessage(level, message, meta = {}) {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      level: level.toUpperCase(),
      message,
      service: 'sparkpost-webhook',
      environment: process.env.NODE_ENV || 'development',
      ...meta
    };

    // Remove sensitive data from logs
    const sanitized = this.sanitizeLogData(logEntry);
    return JSON.stringify(sanitized);
  }

  sanitizeLogData(data) {
    const sensitiveKeys = [
      'password', 'secret', 'token', 'apikey', 'api_key',
      'auth', 'authorization', 'x-api-key', 'cookie',
      'x-sparkpost-webhook-signature'
    ];

    const sensitized = { ...data };

    // Recursively sanitize nested objects
    const sanitizeObject = (obj) => {
      if (!obj || typeof obj !== 'object') return obj;

      const result = Array.isArray(obj) ? [] : {};
      
      for (const [key, value] of Object.entries(obj)) {
        const lowerKey = key.toLowerCase();
        
        if (sensitiveKeys.some(sensitive => lowerKey.includes(sensitive))) {
          result[key] = '[REDACTED]';
        } else if (typeof value === 'object' && value !== null) {
          result[key] = sanitizeObject(value);
        } else {
          result[key] = value;
        }
      }
      
      return result;
    };

    return sanitizeObject(sensitized);
  }

  shouldLog(level) {
    return this.levels[level] <= this.currentLevel;
  }

  error(message, meta = {}) {
    if (this.shouldLog('error')) {
      console.error(this.formatMessage('error', message, meta));
    }
  }

  warn(message, meta = {}) {
    if (this.shouldLog('warn')) {
      console.warn(this.formatMessage('warn', message, meta));
    }
  }

  info(message, meta = {}) {
    if (this.shouldLog('info')) {
      console.log(this.formatMessage('info', message, meta));
    }
  }

  debug(message, meta = {}) {
    if (this.shouldLog('debug')) {
      console.log(this.formatMessage('debug', message, meta));
    }
  }

  // Enhanced method for logging HTTP requests with optional headers
  logRequest(req, res, responseTime) {
    const logData = {
      method: req.method,
      url: req.url,
      userAgent: req.get('User-Agent'),
      ip: req.ip || req.connection.remoteAddress,
      statusCode: res.statusCode,
      responseTime: `${responseTime}ms`,
      contentLength: res.get('content-length') || 0,
      contentType: req.get('Content-Type')
    };

    // Include headers in debug mode if enabled
    if (this.logHttpHeaders && this.shouldLog('debug')) {
      logData.headers = this.sanitizeLogData(req.headers);
    }

    // Include query parameters if present
    if (req.query && Object.keys(req.query).length > 0) {
      logData.query = req.query;
    }

    this.info('HTTP Request', logData);
  }

  // Enhanced method for logging webhook requests with full details
  logWebhookRequest(req, eventCount = 0, sampleEvent = null) {
    const logData = {
      method: req.method,
      url: req.url,
      userAgent: req.get('User-Agent'),
      ip: req.ip || req.connection.remoteAddress,
      contentType: req.get('Content-Type'),
      contentLength: req.get('Content-Length'),
      eventCount
    };

    // Include headers in debug mode if enabled
    if (this.logHttpHeaders && this.shouldLog('debug')) {
      logData.headers = this.sanitizeLogData(req.headers);
    }

    // Include sample event data if provided
    if (sampleEvent) {
      logData.sampleEvent = sampleEvent;
    }

    // Include SparkPost specific headers
    const sparkpostHeaders = {};
    Object.keys(req.headers).forEach(key => {
      if (key.toLowerCase().startsWith('x-sparkpost') || 
          key.toLowerCase().startsWith('x-messagesystems')) {
        sparkpostHeaders[key] = req.headers[key];
      }
    });

    if (Object.keys(sparkpostHeaders).length > 0) {
      logData.sparkpostHeaders = sparkpostHeaders;
    }

    this.info('Webhook request received', logData);
  }

  // Method for logging authentication attempts with details
  logAuthAttempt(req, authType, result) {
    const logData = {
      method: req.method,
      url: req.url,
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent'),
      authType,
      success: result.valid,
      reason: result.reason
    };

    // Include auth-related headers (sanitized)
    if (this.logHttpHeaders && this.shouldLog('debug')) {
      const authHeaders = {};
      if (req.headers.authorization) {
        const authHeader = req.headers.authorization;
        if (authHeader.startsWith('Basic ')) {
          authHeaders.authorization = 'Basic [REDACTED]';
        } else if (authHeader.startsWith('Bearer ')) {
          authHeaders.authorization = `Bearer ${authHeader.substring(7, 20)}...`;
        } else {
          authHeaders.authorization = '[REDACTED]';
        }
      }
      
      // Include other potentially relevant headers
      ['x-real-ip', 'x-forwarded-for', 'x-forwarded-proto'].forEach(header => {
        if (req.headers[header]) {
          authHeaders[header] = req.headers[header];
        }
      });

      if (Object.keys(authHeaders).length > 0) {
        logData.authHeaders = authHeaders;
      }
    }

    // Add result-specific data
    if (result.username) {
      logData.username = result.username;
    }
    if (result.clientId) {
      logData.clientId = result.clientId;
    }
    if (result.error) {
      logData.error = result.error;
    }

    const level = result.valid ? 'info' : 'warn';
    this[level]('Authentication attempt', logData);
  }

  // Method for logging errors with stack traces
  logError(error, context = {}) {
    const errorLog = {
      name: error.name,
      message: error.message,
      stack: error.stack,
      context
    };

    this.error('Application Error', errorLog);
  }

  // Method for logging detailed validation errors
  logValidationError(error, context = {}) {
    const logData = {
      error: error.message,
      details: error.details || [],
      context
    };

    this.warn('Validation Error', logData);
  }
}

// Export singleton instance
const logger = new Logger();

module.exports = { logger };