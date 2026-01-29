// ======================= SECURITY AUDIT LOGGING MIDDLEWARE =======================
// Purpose: Track all authentication, authorization, and security-critical events
// Requirement: Lab Evaluation 1 - Security monitoring and compliance
// Used By: Backend routes for logging access attempts, role changes, admin actions
// ========================================================================================

const fs = require('fs');
const path = require('path');

const LOG_FILE = path.join(__dirname, '../logs/security-audit.log');

// Ensure logs directory exists
const logsDir = path.dirname(LOG_FILE);
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

/**
 * Log security event to file with timestamp and severity
 * 
 * @param {string} eventType - Type of event (LOGIN, FAILED_LOGIN, ACCESS_DENIED, SIGNUP, etc.)
 * @param {Object} details - Event details (email, ip, role, etc.)
 * @param {string} severity - Event severity (INFO, WARNING, ERROR, CRITICAL)
 */
function logSecurityEvent(eventType, details = {}, severity = 'INFO') {
  const timestamp = new Date().toISOString();
  
  const logEntry = {
    timestamp,
    eventType,
    severity,
    details,
    ip: details.ip || 'unknown',
    email: details.email || 'anonymous',
    userId: details.userId || 'N/A',
    role: details.role || 'guest'
  };
  
  // Format log entry as JSON for easy parsing
  const logLine = JSON.stringify(logEntry) + '\n';
  
  // Append to log file
  fs.appendFileSync(LOG_FILE, logLine, 'utf-8');
  
  // Also log to console in development
  console.log(`[${severity}] ${eventType} - ${details.email || 'anonymous'} at ${timestamp}`);
}

/**
 * Express middleware to extract client IP address
 */
function getClientIp(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0] ||
    req.socket.remoteAddress ||
    'unknown'
  );
}

/**
 * Middleware for login attempt logging
 * Purpose: Log successful and failed login attempts
 * 
 * Usage: app.post('/api/auth/login', logLoginAttempt, loginHandler)
 */
function logLoginAttempt(req, res, next) {
  const originalJson = res.json;
  
  res.json = function(data) {
    const ip = getClientIp(req);
    const email = req.body.email;
    const role = req.body.role || 'user';
    
    // Check if this will be a successful response
    if (data.message === "OTP sent to email" || data.token) {
      logSecurityEvent('LOGIN_ATTEMPT_SUCCESS', {
        email,
        role,
        ip
      }, 'INFO');
    } else if (data.message?.includes('Wrong') || data.message?.includes('not found')) {
      logSecurityEvent('LOGIN_ATTEMPT_FAILED', {
        email,
        role,
        reason: data.message,
        ip
      }, 'WARNING');
    } else if (data.message?.includes('not allowed')) {
      logSecurityEvent('UNAUTHORIZED_ADMIN_ACCESS', {
        email,
        attemptedRole: 'admin',
        reason: data.message,
        ip
      }, 'CRITICAL');
    }
    
    return originalJson.call(this, data);
  };
  
  next();
}

/**
 * Middleware for OTP verification logging
 * Purpose: Log OTP verification attempts
 */
function logOtpVerification(req, res, next) {
  const originalJson = res.json;
  
  res.json = function(data) {
    const ip = getClientIp(req);
    const email = req.body.email;
    
    if (data.token) {
      logSecurityEvent('OTP_VERIFICATION_SUCCESS', {
        email,
        role: data.role,
        ip
      }, 'INFO');
    } else if (data.message?.includes('Invalid') || data.message?.includes('expired')) {
      logSecurityEvent('OTP_VERIFICATION_FAILED', {
        email,
        reason: data.message,
        ip
      }, 'WARNING');
    }
    
    return originalJson.call(this, data);
  };
  
  next();
}

/**
 * Middleware for registration logging
 * Purpose: Log all user registration attempts
 */
function logRegistration(req, res, next) {
  const originalJson = res.json;
  
  res.json = function(data) {
    const ip = getClientIp(req);
    const email = req.body.email;
    
    if (data.message?.includes('successfully')) {
      logSecurityEvent('USER_REGISTRATION_SUCCESS', {
        email,
        ip
      }, 'INFO');
    } else if (data.message?.includes('already exists')) {
      logSecurityEvent('DUPLICATE_REGISTRATION_ATTEMPT', {
        email,
        ip
      }, 'WARNING');
    } else {
      logSecurityEvent('REGISTRATION_FAILED', {
        email,
        reason: data.message,
        ip
      }, 'ERROR');
    }
    
    return originalJson.call(this, data);
  };
  
  next();
}

/**
 * Middleware to log admin access attempts
 * Purpose: Track all admin portal access
 * 
 * Usage: app.get('/api/admin/*', logAdminAccess, adminHandler)
 */
function logAdminAccess(req, res, next) {
  const ip = getClientIp(req);
  const token = req.headers.authorization;
  
  // Try to extract user info from token
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join('')
    );
    const payload = JSON.parse(jsonPayload);
    
    if (payload.role === 'admin' && payload.email === 'admin@gmail.com') {
      logSecurityEvent('ADMIN_ACCESS_GRANTED', {
        email: payload.email,
        userId: payload.id,
        resource: req.path,
        method: req.method,
        ip
      }, 'INFO');
    } else {
      logSecurityEvent('UNAUTHORIZED_ADMIN_ACCESS_ATTEMPT', {
        email: payload.email,
        attemptedRole: payload.role,
        resource: req.path,
        method: req.method,
        ip
      }, 'CRITICAL');
    }
  } catch (e) {
    logSecurityEvent('INVALID_TOKEN_ACCESS_ATTEMPT', {
      resource: req.path,
      method: req.method,
      ip
    }, 'CRITICAL');
  }
  
  next();
}

/**
 * Middleware to log profile updates
 * Purpose: Track all user profile and sensitive data changes
 */
function logProfileUpdate(req, res, next) {
  const originalJson = res.json;
  
  res.json = function(data) {
    const ip = getClientIp(req);
    const token = req.headers.authorization;
    
    try {
      const base64Url = token.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      const jsonPayload = decodeURIComponent(
        atob(base64).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join('')
      );
      const payload = JSON.parse(jsonPayload);
      
      logSecurityEvent('PROFILE_UPDATE', {
        email: payload.email,
        userId: payload.id,
        updatedFields: Object.keys(req.body),
        ip
      }, 'INFO');
    } catch (e) {
      // Silent catch - don't fail the request
    }
    
    return originalJson.call(this, data);
  };
  
  next();
}

/**
 * Middleware to log data access
 * Purpose: Track access to orders, products, user data
 */
function logDataAccess(resourceType) {
  return (req, res, next) => {
    const originalJson = res.json;
    
    res.json = function(data) {
      const ip = getClientIp(req);
      const token = req.headers.authorization;
      
      try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(
          atob(base64).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join('')
        );
        const payload = JSON.parse(jsonPayload);
        
        logSecurityEvent(`${resourceType.toUpperCase()}_ACCESS`, {
          email: payload.email,
          userId: payload.id,
          resource: req.path,
          method: req.method,
          ip
        }, 'INFO');
      } catch (e) {
        // Silent catch
      }
      
      return originalJson.call(this, data);
    };
    
    next();
  };
}

/**
 * Generate security audit report
 * Purpose: Analyze logs for suspicious activity
 * 
 * @param {number} hoursToCheck - Number of hours to look back (default: 24)
 * @returns {Object} - Security report with event counts and anomalies
 */
function generateAuditReport(hoursToCheck = 24) {
  if (!fs.existsSync(LOG_FILE)) {
    return { message: 'No audit logs found' };
  }
  
  const logs = fs.readFileSync(LOG_FILE, 'utf-8').split('\n').filter(line => line);
  const cutoffTime = new Date(Date.now() - hoursToCheck * 60 * 60 * 1000);
  
  const report = {
    timeframe: `Last ${hoursToCheck} hours`,
    generatedAt: new Date().toISOString(),
    totalEvents: 0,
    byType: {},
    bySeverity: { INFO: 0, WARNING: 0, ERROR: 0, CRITICAL: 0 },
    failedLoginAttempts: 0,
    adminAccessAttempts: 0,
    unauthorizedAttempts: 0,
    uniqueUsers: new Set(),
    uniqueIPs: new Set()
  };
  
  logs.forEach(line => {
    try {
      const event = JSON.parse(line);
      const eventTime = new Date(event.timestamp);
      
      if (eventTime >= cutoffTime) {
        report.totalEvents++;
        report.byType[event.eventType] = (report.byType[event.eventType] || 0) + 1;
        report.bySeverity[event.severity]++;
        
        if (event.eventType === 'LOGIN_ATTEMPT_FAILED') report.failedLoginAttempts++;
        if (event.eventType.includes('ADMIN_ACCESS')) report.adminAccessAttempts++;
        if (event.eventType.includes('UNAUTHORIZED')) report.unauthorizedAttempts++;
        
        if (event.email && event.email !== 'anonymous') report.uniqueUsers.add(event.email);
        if (event.ip && event.ip !== 'unknown') report.uniqueIPs.add(event.ip);
      }
    } catch (e) {
      // Skip unparseable lines
    }
  });
  
  // Convert sets to counts
  report.uniqueUsers = report.uniqueUsers.size;
  report.uniqueIPs = report.uniqueIPs.size;
  
  // Flag anomalies
  report.anomalies = [];
  if (report.failedLoginAttempts > 10) {
    report.anomalies.push('⚠️ High number of failed login attempts detected');
  }
  if (report.unauthorizedAttempts > 5) {
    report.anomalies.push('🚨 Multiple unauthorized access attempts detected');
  }
  
  return report;
}

// Export middleware functions
module.exports = {
  logSecurityEvent,
  getClientIp,
  logLoginAttempt,
  logOtpVerification,
  logRegistration,
  logAdminAccess,
  logProfileUpdate,
  logDataAccess,
  generateAuditReport
};
