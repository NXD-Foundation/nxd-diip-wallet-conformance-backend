/**
 * Session-Scoped Logging Utilities
 * Provides structured logging with session context for VCI v1.0 and VP v1.0 flows
 */

// ============================================================================
// SESSION CONTEXT MANAGEMENT
// ============================================================================

// AsyncLocalStorage for maintaining session context across async operations
import { AsyncLocalStorage } from 'async_hooks';

const sessionContext = new AsyncLocalStorage();

/**
 * Set the current session context for logging
 * @param {string} sessionId - Session identifier
 */
export function setSessionContext(sessionId) {
  const store = sessionContext.getStore() || {};
  store.sessionId = sessionId;
  // Note: We can't actually "set" the store; this function is typically called
  // within sessionContext.run() to establish the context
}

/**
 * Get the current session context
 * @returns {string|null} - Current session ID or null
 */
export function getSessionContext() {
  const store = sessionContext.getStore();
  return store?.sessionId || null;
}

/**
 * Clear the current session context
 */
export function clearSessionContext() {
  // Context is automatically cleared when the async scope ends
}

/**
 * Run a function with a specific session context
 * @param {string} sessionId - Session identifier
 * @param {Function} fn - Function to run with the session context
 * @returns {*} - Result of the function
 */
export function runWithSessionContext(sessionId, fn) {
  return sessionContext.run({ sessionId }, fn);
}

// ============================================================================
// LOGGING LEVELS AND FORMATTERS
// ============================================================================

const LOG_LEVELS = {
  DEBUG: 'DEBUG',
  INFO: 'INFO',
  WARN: 'WARN',
  ERROR: 'ERROR',
};

/**
 * Format a log entry with session context
 * @param {string} level - Log level
 * @param {string} sessionId - Session identifier
 * @param {string} message - Log message
 * @param {Object} metadata - Additional metadata
 * @returns {Object} - Formatted log entry
 */
function formatLogEntry(level, sessionId, message, metadata = {}) {
  return {
    timestamp: new Date().toISOString(),
    level,
    sessionId: sessionId || 'unknown',
    message,
    ...metadata,
  };
}

// ============================================================================
// SESSION LOGGER FACTORY
// ============================================================================

/**
 * Create a session-scoped logger
 * @param {string} sessionId - Session identifier
 * @returns {Object} - Logger object with log methods
 */
export function makeSessionLogger(sessionId) {
  const log = (level, message, metadata = {}) => {
    const entry = formatLogEntry(level, sessionId, message, metadata);
    const logMessage = `[${entry.timestamp}] [${entry.level}] [session:${entry.sessionId}] ${entry.message}`;
    
    switch (level) {
      case LOG_LEVELS.ERROR:
        console.error(logMessage, metadata.error ? metadata : '');
        break;
      case LOG_LEVELS.WARN:
        console.warn(logMessage, Object.keys(metadata).length > 0 ? metadata : '');
        break;
      case LOG_LEVELS.DEBUG:
        if (process.env.DEBUG === 'true' || process.env.NODE_ENV === 'development') {
          console.log(logMessage, Object.keys(metadata).length > 0 ? metadata : '');
        }
        break;
      default:
        console.log(logMessage, Object.keys(metadata).length > 0 ? metadata : '');
    }
    
    return entry;
  };

  return {
    debug: (message, metadata = {}) => log(LOG_LEVELS.DEBUG, message, metadata),
    info: (message, metadata = {}) => log(LOG_LEVELS.INFO, message, metadata),
    warn: (message, metadata = {}) => log(LOG_LEVELS.WARN, message, metadata),
    error: (message, metadata = {}) => log(LOG_LEVELS.ERROR, message, metadata),
    sessionId,
  };
}

// ============================================================================
// HTTP REQUEST/RESPONSE LOGGING
// ============================================================================

/**
 * Log HTTP request details
 * @param {Object} req - Express request object
 * @param {string} sessionId - Session identifier
 * @param {Object} additionalData - Additional data to log
 */
export function logHttpRequest(req, sessionId, additionalData = {}) {
  const logger = makeSessionLogger(sessionId);
  
  logger.info('HTTP Request', {
    method: req.method,
    url: req.originalUrl || req.url,
    path: req.path,
    query: Object.keys(req.query || {}).length > 0 ? req.query : undefined,
    headers: {
      'content-type': req.headers['content-type'],
      'authorization': req.headers['authorization'] ? '[REDACTED]' : undefined,
      'dpop': req.headers['dpop'] ? '[PRESENT]' : undefined,
    },
    bodyKeys: Object.keys(req.body || {}),
    ...additionalData,
  });
}

/**
 * Log HTTP response details
 * @param {Object} res - Express response object
 * @param {string} sessionId - Session identifier
 * @param {number} statusCode - HTTP status code
 * @param {Object} additionalData - Additional data to log
 */
export function logHttpResponse(req, res, sessionId, statusCode, additionalData = {}) {
  const logger = makeSessionLogger(sessionId);
  const level = statusCode >= 400 ? (statusCode >= 500 ? 'error' : 'warn') : 'info';
  
  logger[level]('HTTP Response', {
    statusCode,
    method: req.method,
    url: req.originalUrl || req.url,
    ...additionalData,
  });
}

// ============================================================================
// EXPRESS MIDDLEWARE
// ============================================================================

/**
 * Express middleware to bind session context to request/response lifecycle
 * @returns {Function} Express middleware
 */
export function sessionLoggingMiddleware() {
  return (req, res, next) => {
    // Extract session ID from various sources
    const sessionId = 
      req.query?.sessionId ||
      req.params?.id ||
      req.params?.sessionId ||
      req.body?.sessionId ||
      req.headers?.['x-session-id'] ||
      null;
    
    if (sessionId) {
      req.sessionLoggingId = sessionId;
      res.locals = res.locals || {};
      res.locals.sessionLoggingId = sessionId;
      
      // Create logger and attach to request
      req.sessionLogger = makeSessionLogger(sessionId);
    }
    
    next();
  };
}

/**
 * Bind session logging context to request/response
 * @param {Object} req - Express request
 * @param {Object} res - Express response
 * @param {string} sessionId - Session identifier
 * @returns {string|null} - The bound session ID
 */
export function bindSessionLoggingContext(req, res, sessionId) {
  if (!sessionId) {
    return null;
  }

  if (req) {
    req.sessionLoggingId = sessionId;
    req.sessionLogger = makeSessionLogger(sessionId);
  }

  if (res) {
    res.locals = res.locals || {};
    res.locals.sessionLoggingId = sessionId;
  }

  return sessionId;
}

// ============================================================================
// ASYNC LOGGING FUNCTIONS (Compatible with cacheServiceRedis patterns)
// ============================================================================

/**
 * Log info level message (async interface for compatibility)
 * @param {string} sessionId - Session identifier
 * @param {string} message - Log message
 * @param {Object} metadata - Additional metadata
 * @returns {Promise<void>}
 */
export async function logInfo(sessionId, message, metadata = {}) {
  const logger = makeSessionLogger(sessionId);
  logger.info(message, metadata);
}

/**
 * Log debug level message (async interface for compatibility)
 * @param {string} sessionId - Session identifier
 * @param {string} message - Log message
 * @param {Object} metadata - Additional metadata
 * @returns {Promise<void>}
 */
export async function logDebug(sessionId, message, metadata = {}) {
  const logger = makeSessionLogger(sessionId);
  logger.debug(message, metadata);
}

/**
 * Log warning level message (async interface for compatibility)
 * @param {string} sessionId - Session identifier
 * @param {string} message - Log message
 * @param {Object} metadata - Additional metadata
 * @returns {Promise<void>}
 */
export async function logWarn(sessionId, message, metadata = {}) {
  const logger = makeSessionLogger(sessionId);
  logger.warn(message, metadata);
}

/**
 * Log error level message (async interface for compatibility)
 * @param {string} sessionId - Session identifier
 * @param {string} message - Log message
 * @param {Object} metadata - Additional metadata
 * @returns {Promise<void>}
 */
export async function logError(sessionId, message, metadata = {}) {
  const logger = makeSessionLogger(sessionId);
  logger.error(message, metadata);
}

export default {
  makeSessionLogger,
  logHttpRequest,
  logHttpResponse,
  sessionLoggingMiddleware,
  bindSessionLoggingContext,
  setSessionContext,
  getSessionContext,
  clearSessionContext,
  runWithSessionContext,
  logInfo,
  logDebug,
  logWarn,
  logError,
};
