const { logger } = require('./logger');
const { sanitizeInput } = require('./validation');

// SparkPost index configuration
const SPARKPOST_INDEX_PREFIX = 'sparkpost-events';
const INDEX_MAPPING = {
  mappings: {
    properties: {
      '@timestamp': { type: 'date' },
      event_id: { type: 'keyword' },
      type: { type: 'keyword' },
      timestamp: { type: 'date' },
      message_id: { type: 'keyword' },
      transmission_id: { type: 'keyword' },
      campaign_id: { type: 'keyword' },
      customer_id: { type: 'keyword' },
      template_id: { type: 'keyword' },
      template_version: { type: 'keyword' },
      recipient: { type: 'keyword' },
      recipient_domain: { type: 'keyword' },
      recipient_type: { type: 'keyword' },
      subject: { 
        type: 'text',
        fields: {
          keyword: { type: 'keyword', ignore_above: 256 }
        }
      },
      friendly_from: { type: 'keyword' },
      msg_from: { type: 'keyword' },
      msg_size: { type: 'long' },
      user_agent: {
        type: 'text',
        fields: {
          keyword: { type: 'keyword', ignore_above: 512 }
        }
      },
      ip_address: { type: 'ip' },
      geo_ip: {
        properties: {
          country: { type: 'keyword' },
          region: { type: 'keyword' },
          city: { type: 'keyword' },
          location: { type: 'geo_point' }
        }
      },
      target_link_name: { type: 'keyword' },
      target_link_url: { 
        type: 'text',
        fields: {
          keyword: { type: 'keyword', ignore_above: 512 }
        }
      },
      bounce_class: { type: 'integer' },
      reason: {
        type: 'text',
        fields: {
          keyword: { type: 'keyword', ignore_above: 256 }
        }
      },
      error_code: { type: 'keyword' },
      delivery_method: { type: 'keyword' },
      raw_reason: {
        type: 'text',
        fields: {
          keyword: { type: 'keyword', ignore_above: 512 }
        }
      },
      queue_time: { type: 'keyword' },
      rcpt_meta: { type: 'object', enabled: false },
      rcpt_tags: { type: 'keyword' },
      msg_meta: { type: 'object', enabled: false },
      routing_domain: { type: 'keyword' },
      sending_ip: { type: 'ip' },
      subaccount_id: { type: 'keyword' },
      processed_at: { type: 'date' },
      event_category: { type: 'keyword' }
    }
  },
  settings: {
    number_of_shards: 1,
    number_of_replicas: 1
  }
};

// Generate index name with date
function generateIndexName() {
  const date = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
  return `${SPARKPOST_INDEX_PREFIX}-${date}`;
}

// Ensure SparkPost index exists with proper mapping
async function ensureIndexExists(client) {
  const indexName = generateIndexName();
  
  try {
    const exists = await client.indices.exists({ index: indexName });
    
    if (!exists) {
      logger.info(`Creating SparkPost index: ${indexName}`);
      
      await client.indices.create({
        index: indexName,
        body: INDEX_MAPPING
      });
      
      logger.info(`Successfully created index: ${indexName}`);
    }
    
    return indexName;
  } catch (error) {
    logger.error(`Failed to ensure index exists: ${error.message}`);
    throw error;
  }
}

// Transform SparkPost event for Elasticsearch
function transformEvent(event) {
  const transformed = {
    ...event,
    '@timestamp': new Date().toISOString(),
    processed_at: new Date().toISOString()
  };

  // Sanitize string fields
  Object.keys(transformed).forEach(key => {
    if (typeof transformed[key] === 'string') {
      transformed[key] = sanitizeInput(transformed[key]);
    }
  });

  // Transform geo_ip location for Elasticsearch geo_point
  if (event.geo_ip && event.geo_ip.latitude && event.geo_ip.longitude) {
    transformed.geo_ip = {
      ...event.geo_ip,
      location: {
        lat: event.geo_ip.latitude,
        lon: event.geo_ip.longitude
      }
    };
  }

  // Ensure timestamp is properly formatted
  if (event.timestamp) {
    try {
      transformed.timestamp = new Date(event.timestamp).toISOString();
    } catch (error) {
      logger.warn(`Invalid timestamp format: ${event.timestamp}`);
      transformed.timestamp = new Date().toISOString();
    }
  }

  // Add event categorization
  transformed.event_category = categorizeEvent(event.type);

  return transformed;
}

// Categorize events for better analytics
function categorizeEvent(eventType) {
  const categories = {
    'delivery': 'engagement',
    'injection': 'sending',
    'bounce': 'delivery_failure',
    'delay': 'delivery_issue',
    'policy_rejection': 'delivery_failure',
    'out_of_band': 'delivery_failure',
    'open': 'engagement',
    'click': 'engagement',
    'generation_failure': 'sending_failure',
    'generation_rejection': 'sending_failure',
    'spam_complaint': 'reputation',
    'unsubscribe': 'engagement',
    'relay_injection': 'relay',
    'relay_rejection': 'relay',
    'relay_delivery': 'relay',
    'relay_tempfail': 'relay',
    'relay_permfail': 'relay',
    'list_unsubscribe': 'engagement',
    'link_unsubscribe': 'engagement'
  };

  return categories[eventType] || 'other';
}

// Process events and send to Elasticsearch
async function processEvents(events, client) {
  try {
    // Ensure index exists
    const indexName = await ensureIndexExists(client);

    // Prepare bulk operations
    const bulkOperations = [];
    
    for (const event of events) {
      const transformedEvent = transformEvent(event);
      
      // Add index operation
      bulkOperations.push({
        index: {
          _index: indexName,
          _id: event.event_id // Use event_id as document ID for deduplication
        }
      });
      
      // Add document data
      bulkOperations.push(transformedEvent);
    }

    // Execute bulk operation
    const response = await client.bulk({
      body: bulkOperations,
      refresh: false // Don't wait for refresh for better performance
    });

    // Check for errors
    if (response.errors) {
      const erroredDocuments = response.items.filter(item => item.index?.error);
      logger.warn(`Some documents failed to index: ${erroredDocuments.length}`);
      
      erroredDocuments.forEach(doc => {
        logger.error('Index error:', doc.index.error);
      });
    }

    const successful = response.items.filter(item => !item.index?.error).length;
    
    logger.info(`Successfully indexed ${successful}/${events.length} events to ${indexName}`);

    return {
      processed: successful,
      failed: events.length - successful,
      indexName
    };

  } catch (error) {
    logger.error('Failed to process events:', error);
    throw error;
  }
}

// Health check for Elasticsearch connection
async function healthCheck(client) {
  try {
    const health = await client.cluster.health();
    return {
      status: 'healthy',
      cluster_status: health.status,
      number_of_nodes: health.number_of_nodes
    };
  } catch (error) {
    logger.error('Elasticsearch health check failed:', error);
    return {
      status: 'unhealthy',
      error: error.message
    };
  }
}

module.exports = {
  processEvents,
  healthCheck,
  ensureIndexExists,
  transformEvent,
  generateIndexName
};