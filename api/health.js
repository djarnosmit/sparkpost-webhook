const { healthCheck } = require('../lib/eventProcessor');
const { logger } = require('../lib/logger');

module.exports = async (req, res) => {
  // Only allow GET requests
  if (req.method !== 'GET') {
    return res.status(405).json({ 
      error: 'Method not allowed',
      message: 'Only GET requests are supported'
    });
  }

  try {
    const startTime = Date.now();
    
    // Check if Elasticsearch is configured
    const isElasticsearchConfigured = process.env.ELASTICSEARCH_CLOUD_ID && process.env.ELASTICSEARCH_API_KEY;
    let esHealth;
    
    if (isElasticsearchConfigured) {
      // Initialize Elasticsearch client only if configured
      const { Client } = require('@elastic/elasticsearch');
      const elasticsearch = new Client({
        cloud: {
          id: process.env.ELASTICSEARCH_CLOUD_ID
        },
        auth: {
          apiKey: process.env.ELASTICSEARCH_API_KEY
        }
      });
      
      esHealth = await healthCheck(elasticsearch);
    } else {
      esHealth = {
        status: 'not_configured',
        message: 'Elasticsearch credentials not provided (normal in development)'
      };
    }
    
    const responseTime = Date.now() - startTime;
    
    const healthStatus = {
      status: isElasticsearchConfigured && esHealth.status === 'healthy' ? 'healthy' : 'degraded',
      timestamp: new Date().toISOString(),
      service: 'sparkpost-webhook',
      version: '1.0.0',
      environment: process.env.NODE_ENV || 'development',
      responseTime: `${responseTime}ms`,
      checks: {
        elasticsearch: esHealth
      }
    };

    // Return 200 even if Elasticsearch is not configured (for development)
    const statusCode = isElasticsearchConfigured ? 
      (esHealth.status === 'healthy' ? 200 : 503) : 
      200;

    return res.status(statusCode).json(healthStatus);

  } catch (error) {
    logger.error('Health check failed:', error);
    
    return res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      service: 'sparkpost-webhook',
      error: 'Health check failed',
      message: error.message
    });
  }
};