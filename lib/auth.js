const crypto = require('crypto');
const { logger } = require('./logger');

// OAuth JWT verification (simplified - you might want to use a library like jsonwebtoken for production)
async function verifyJWT(token, jwksEndpoint, audience, allowedScopes) {
  try {
    // This is a basic implementation. For production, consider using:
    // - jsonwebtoken library
    // - jwks-rsa for JWKS management
    // - Proper JWT validation with all security checks
    
    logger.debug('Verifying JWT token', { 
      jwksEndpoint, 
      audience,
      allowedScopes,
      tokenHeader: token.substring(0, 20) + '...'
    });

    // For now, we'll implement basic JWT structure validation
    // In production, you should use a proper JWT library
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }

    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

    logger.debug('JWT payload decoded', { 
      header: { alg: header.alg, typ: header.typ },
      payload: { 
        iss: payload.iss, 
        aud: payload.aud, 
        exp: payload.exp,
        scope: payload.scope 
      }
    });

    // Basic validation checks
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      throw new Error('Token expired');
    }

    if (audience && payload.aud !== audience) {
      throw new Error(`Invalid audience. Expected: ${audience}, got: ${payload.aud}`);
    }

    // Check scopes if provided
    if (allowedScopes && allowedScopes.length > 0) {
      const tokenScopes = payload.scope ? payload.scope.split(' ') : [];
      const hasRequiredScope = allowedScopes.some(scope => tokenScopes.includes(scope));
      
      if (!hasRequiredScope) {
        throw new Error(`Insufficient scope. Required one of: ${allowedScopes.join(', ')}, got: ${tokenScopes.join(', ')}`);
      }
    }

    // Note: In production, you should verify the signature using the JWKS endpoint
    // This is just a basic validation for structure and claims
    logger.info('JWT validation passed (signature verification skipped in this implementation)');
    
    return {
      valid: true,
      payload,
      clientId: payload.client_id || payload.sub
    };

  } catch (error) {
    logger.error('JWT verification failed', { error: error.message });
    return {
      valid: false,
      error: error.message
    };
  }
}

// Validate SparkPost Basic Auth
function validateBasicAuth(req) {
  const username = process.env.SPARKPOST_WEBHOOK_USERNAME;
  const password = process.env.SPARKPOST_WEBHOOK_PASSWORD;
  
  if (!username || !password) {
    logger.debug('Basic Auth credentials not configured');
    return { valid: false, reason: 'credentials_not_configured' };
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    logger.warn('Missing or invalid Basic Authorization header');
    return { valid: false, reason: 'missing_auth_header' };
  }

  try {
    const base64Credentials = authHeader.slice(6); // Remove 'Basic '
    const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
    const [reqUsername, reqPassword] = credentials.split(':');
    
    logger.debug('Basic Auth attempt', { 
      username: reqUsername,
      hasPassword: !!reqPassword,
      expectedUsername: username
    });
    
    // Use timing-safe comparison to prevent timing attacks
    const usernameMatch = crypto.timingSafeEqual(
      Buffer.from(username),
      Buffer.from(reqUsername || '')
    );
    const passwordMatch = crypto.timingSafeEqual(
      Buffer.from(password),
      Buffer.from(reqPassword || '')
    );
    
    const isValid = usernameMatch && passwordMatch;
    
    if (isValid) {
      logger.info('Basic Auth validation successful', { username: reqUsername });
    } else {
      logger.warn('Basic Auth validation failed', { 
        username: reqUsername,
        usernameMatch,
        passwordMatch: !!reqPassword
      });
    }
    
    return { 
      valid: isValid, 
      reason: isValid ? 'success' : 'invalid_credentials',
      username: reqUsername
    };
    
  } catch (error) {
    logger.error('Basic Auth validation error', { error: error.message });
    return { valid: false, reason: 'validation_error', error: error.message };
  }
}

// Validate OAuth Bearer token
async function validateOAuth(req) {
  const clientId = process.env.SPARKPOST_OAUTH_CLIENT_ID;
  const jwksEndpoint = process.env.SPARKPOST_OAUTH_JWKS_ENDPOINT;
  const audience = process.env.SPARKPOST_OAUTH_AUDIENCE;
  const scopes = process.env.SPARKPOST_OAUTH_SCOPES ? process.env.SPARKPOST_OAUTH_SCOPES.split(',') : [];
  
  if (!clientId || !jwksEndpoint) {
    logger.debug('OAuth configuration not complete');
    return { valid: false, reason: 'oauth_not_configured' };
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    logger.warn('Missing or invalid Bearer Authorization header');
    return { valid: false, reason: 'missing_bearer_token' };
  }

  try {
    const token = authHeader.slice(7); // Remove 'Bearer '
    
    logger.debug('OAuth validation attempt', { 
      clientId,
      jwksEndpoint,
      audience,
      scopes,
      tokenLength: token.length
    });
    
    const result = await verifyJWT(token, jwksEndpoint, audience, scopes);
    
    if (result.valid) {
      logger.info('OAuth validation successful', { 
        clientId: result.clientId,
        audience: audience
      });
      return { 
        valid: true, 
        reason: 'success',
        clientId: result.clientId,
        payload: result.payload
      };
    } else {
      logger.warn('OAuth validation failed', { error: result.error });
      return { 
        valid: false, 
        reason: 'invalid_token',
        error: result.error
      };
    }
    
  } catch (error) {
    logger.error('OAuth validation error', { error: error.message });
    return { valid: false, reason: 'validation_error', error: error.message };
  }
}

// Main authentication function that handles both Basic Auth and OAuth
async function authenticateRequest(req) {
  const authType = process.env.SPARKPOST_AUTH_TYPE?.toLowerCase() || 'none';
  
  logger.debug('Authentication attempt', { 
    authType,
    hasAuthHeader: !!req.headers.authorization,
    authHeaderType: req.headers.authorization?.split(' ')[0],
    userAgent: req.headers['user-agent']
  });

  switch (authType) {
    case 'basic':
      const basicResult = validateBasicAuth(req);
      if (basicResult.valid) {
        logger.info('Request authenticated via Basic Auth', { 
          username: basicResult.username 
        });
      } else {
        logger.warn('Basic Auth failed', { 
          reason: basicResult.reason,
          error: basicResult.error
        });
      }
      return basicResult;

    case 'oauth':
      const oauthResult = await validateOAuth(req);
      if (oauthResult.valid) {
        logger.info('Request authenticated via OAuth', { 
          clientId: oauthResult.clientId 
        });
      } else {
        logger.warn('OAuth failed', { 
          reason: oauthResult.reason,
          error: oauthResult.error
        });
      }
      return oauthResult;

    case 'none':
      logger.info('Authentication disabled - allowing request', { 
        environment: process.env.NODE_ENV 
      });
      return { valid: true, reason: 'auth_disabled' };

    default:
      logger.error('Invalid authentication type configured', { 
        authType,
        validTypes: ['basic', 'oauth', 'none']
      });
      return { 
        valid: false, 
        reason: 'invalid_auth_type',
        error: `Invalid SPARKPOST_AUTH_TYPE: ${authType}. Must be 'basic', 'oauth', or 'none'`
      };
  }
}

module.exports = {
  authenticateRequest,
  validateBasicAuth,
  validateOAuth,
  verifyJWT
};