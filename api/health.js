const { Client } = require('@elastic/elasticsearch');
const { healthCheck } = require('../lib/eventProcessor');
const { logger } = require('../lib/logger');

// Initialize Elasticsearch client
const elasticsearch = new Client({
  cloud: {
    id: process.env.ELASTICSEARCH_CLOUD_ID
  },
  auth: {
    apiKey: process.env.ELASTICSEARCH_API_KEY
  }
});

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
    
    // Check Elasticsearch health
    const esHealth = await healthCheck(elasticsearch);
    
    const responseTime = Date.now() - startTime;
    
    const healthStatus = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: 'sparkpost-webhook',
      version: '1.0.0',
      environment: process.env.NODE_ENV || 'development',
      responseTime: `${responseTime}ms`,
      checks: {
        elasticsearch: esHealth
      }
    };

    // Determine overall health status
    if (esHealth.status !== 'healthy') {
      healthStatus.status = 'unhealthy';
      res.status(503);
    } else {
      res.status(200);
    }

    return res.json(healthStatus);

  } catch (error) {
    logger.error('Health check failed:', error);
    
    return res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      service: 'sparkpost-webhook',
      error: 'Health check failed'
    });
  }
};