// Simple, secure logger for production use
class Logger {
  constructor() {
    this.logLevel = process.env.LOG_LEVEL || 'info';
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

    const sanitized = { ...data };

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

    return sanitizeObject(sanitized);
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

  // Method for logging HTTP requests (without sensitive headers)
  logRequest(req, res, responseTime) {
    const logData = {
      method: req.method,
      url: req.url,
      userAgent: req.get('User-Agent'),
      ip: req.ip || req.connection.remoteAddress,
      statusCode: res.statusCode,
      responseTime: `${responseTime}ms`,
      contentLength: res.get('content-length') || 0
    };

    this.info('HTTP Request', logData);
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
}

// Export singleton instance
const logger = new Logger();

module.exports = { logger };