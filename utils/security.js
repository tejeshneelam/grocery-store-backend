// ==================== DIGITAL SIGNATURE & ENCODING UTILITIES ====================
// Purpose: Implements HMAC-SHA256 digital signatures for data integrity
// and Base64 encoding/decoding for secure data transmission
// Requirement: Lab Evaluation 1 - Hashing/Digital Signature & Encoding Components
// ==================================================================================

const crypto = require('crypto');

// ========== DIGITAL SIGNATURE FUNCTIONS ==========
/**
 * Generate HMAC-SHA256 signature for data integrity verification
 * Purpose: Creates a cryptographic fingerprint of data to detect tampering
 * Used for: Order confirmation, receipt generation, sensitive transactions
 * 
 * @param {Object} data - The data to sign (e.g., order details)
 * @returns {string} - Hex-encoded HMAC-SHA256 signature
 */
function generateSignature(data) {
  // Convert object to consistent JSON string
  const dataString = JSON.stringify(data);
  
  // Create HMAC-SHA256 signature
  // SECRET: In production, use environment variable (process.env.SIGNATURE_SECRET)
  const signature = crypto
    .createHmac('sha256', process.env.SIGNATURE_SECRET || 'ORDER_SIGNATURE_SECRET')
    .update(dataString)
    .digest('hex');
  
  return signature;
}

/**
 * Verify digital signature to ensure data hasn't been tampered with
 * Purpose: Validates data integrity and authenticity
 * Security: Uses timing-safe comparison to prevent timing attacks
 * 
 * @param {Object} data - The original data
 * @param {string} signature - The signature to verify against
 * @returns {boolean} - True if signature is valid, false otherwise
 */
function verifySignature(data, signature) {
  const calculatedSignature = generateSignature(data);
  
  // Use timing-safe comparison to prevent timing attacks
  // Regular string comparison could leak information through timing differences
  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(calculatedSignature)
    );
  } catch (e) {
    return false; // Buffer lengths don't match
  }
}

/**
 * Generate signature for order data
 * Specifically designed for e-commerce order verification
 * 
 * @param {Object} orderData - Order object with userId, items, totalPrice, etc.
 * @returns {string} - Order signature
 */
function generateOrderSignature(orderData) {
  const orderPayload = {
    userId: orderData.userId,
    items: orderData.items,
    totalPrice: orderData.totalPrice,
    timestamp: orderData.timestamp
  };
  
  return generateSignature(orderPayload);
}

/**
 * Verify order hasn't been modified
 * 
 * @param {Object} orderData - Order object
 * @param {string} signature - Order signature to verify
 * @returns {boolean} - True if order is authentic
 */
function verifyOrderSignature(orderData, signature) {
  return verifySignature(orderData, signature);
}

// ========== BASE64 ENCODING/DECODING FUNCTIONS ==========
/**
 * Encode data to Base64
 * Purpose: Convert binary/text data to ASCII-safe Base64 format
 * Use Cases: Product exports, API responses, data transmission
 * 
 * Security Note: Base64 is ENCODING not ENCRYPTION - use only for obfuscation
 *                For sensitive data, encrypt AFTER encoding
 * 
 * @param {string|Object} data - Data to encode
 * @returns {string} - Base64 encoded string
 */
function encodeToBase64(data) {
  // Convert data to string if it's an object
  const stringData = typeof data === 'string' ? data : JSON.stringify(data);
  
  // Encode to Base64
  return Buffer.from(stringData, 'utf-8').toString('base64');
}

/**
 * Decode Base64 to original data
 * Purpose: Convert Base64 back to readable format
 * 
 * @param {string} encodedData - Base64 encoded string
 * @returns {string|Object} - Decoded data (JSON if applicable)
 */
function decodeFromBase64(encodedData) {
  // Decode from Base64
  const decoded = Buffer.from(encodedData, 'base64').toString('utf-8');
  
  // Try to parse as JSON if possible
  try {
    return JSON.parse(decoded);
  } catch (e) {
    // Return as string if not valid JSON
    return decoded;
  }
}

/**
 * Encode product data for secure transmission
 * Purpose: Encode product catalog data for API responses
 * 
 * @param {Array|Object} productData - Product(s) to encode
 * @returns {string} - Base64 encoded product data
 */
function encodeProductData(productData) {
  return encodeToBase64(productData);
}

/**
 * Decode product data from transmission
 * Purpose: Retrieve original product data from encoded form
 * 
 * @param {string} encodedData - Encoded product data
 * @returns {Object|Array} - Original product data
 */
function decodeProductData(encodedData) {
  return decodeFromBase64(encodedData);
}

/**
 * Encode invoice/receipt for secure storage
 * Purpose: Archive orders in compact encoded format
 * 
 * @param {Object} receiptData - Receipt information
 * @returns {string} - Encoded receipt
 */
function encodeReceipt(receiptData) {
  return encodeToBase64({
    receiptId: receiptData.receiptId,
    orderId: receiptData.orderId,
    date: receiptData.date,
    items: receiptData.items,
    total: receiptData.total,
    signature: receiptData.signature
  });
}

/**
 * Decode receipt for viewing
 * Purpose: Retrieve archived receipt data
 * 
 * @param {string} encodedReceipt - Encoded receipt
 * @returns {Object} - Decoded receipt
 */
function decodeReceipt(encodedReceipt) {
  return decodeFromBase64(encodedReceipt);
}

// ========== HASH-BASED VERIFICATION ==========
/**
 * Generate SHA256 hash of data
 * Purpose: Create unique fingerprint of data (one-way function)
 * Different from HMAC: No secret key, used for checksums
 * 
 * @param {string|Object} data - Data to hash
 * @returns {string} - SHA256 hash
 */
function generateHash(data) {
  const stringData = typeof data === 'string' ? data : JSON.stringify(data);
  return crypto
    .createHash('sha256')
    .update(stringData)
    .digest('hex');
}

/**
 * Verify data against its hash
 * Purpose: Check if data matches expected hash
 * 
 * @param {string|Object} data - Data to verify
 * @param {string} expectedHash - Hash to compare against
 * @returns {boolean} - True if data matches hash
 */
function verifyHash(data, expectedHash) {
  const calculatedHash = generateHash(data);
  return crypto.timingSafeEqual(
    Buffer.from(calculatedHash),
    Buffer.from(expectedHash)
  );
}

// ========== COMBINED SECURITY FUNCTIONS ==========
/**
 * Create secure order package with signature and encoding
 * Purpose: Prepare order data for transmission with integrity verification
 * 
 * @param {Object} orderData - Order to secure
 * @returns {Object} - Package with encoded data and signature
 */
function createSecureOrderPackage(orderData) {
  const signature = generateOrderSignature(orderData);
  const encodedData = encodeToBase64(orderData);
  
  return {
    data: encodedData,
    signature: signature,
    hash: generateHash(orderData),
    timestamp: new Date().toISOString()
  };
}

/**
 * Verify and extract secure order package
 * Purpose: Validate received order and extract original data
 * 
 * @param {Object} package - Secure order package
 * @returns {Object|null} - Original order data if valid, null if tampered
 */
function verifyAndExtractOrderPackage(package) {
  // Decode the data first
  const decodedData = decodeFromBase64(package.data);
  
  // Verify signature
  if (!verifySignature(decodedData, package.signature)) {
    console.error('❌ Order signature verification failed - possible tampering detected');
    return null;
  }
  
  // Verify hash
  if (!verifyHash(decodedData, package.hash)) {
    console.error('❌ Order hash verification failed - data may be corrupted');
    return null;
  }
  
  return decodedData;
}

// Export all functions
module.exports = {
  // Digital Signature
  generateSignature,
  verifySignature,
  generateOrderSignature,
  verifyOrderSignature,
  
  // Base64 Encoding/Decoding
  encodeToBase64,
  decodeFromBase64,
  encodeProductData,
  decodeProductData,
  encodeReceipt,
  decodeReceipt,
  
  // Hashing
  generateHash,
  verifyHash,
  
  // Combined Security
  createSecureOrderPackage,
  verifyAndExtractOrderPackage
};
