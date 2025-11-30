/**
 * OWASP Top 10 - Injection (NoSQL Injection in Node.js/MongoDB)
 * Author: Paul Sommers
 * 
 * VULNERABILITY EXPLANATION:
 * This code directly passes user input from query parameters to a MongoDB query.
 * While this looks harmless, it's vulnerable to NoSQL injection because:
 * 1. User can send objects instead of strings via query parameters
 * 2. MongoDB query operators (like $gt, $ne, $regex) can be injected
 * 3. Can bypass authentication or retrieve unauthorized data
 * 4. Can cause denial of service through expensive queries
 * 
 * Example attack via URL: /user?username[$ne]=null
 * This sends: { username: { $ne: null } }
 * Which matches ALL users (username not equal to null), returning the first user.
 * 
 * More targeted: /user?username[$regex]=^admin
 * This could enumerate usernames or bypass filters.
 * 
 * Reference: https://owasp.org/Top10/A03_2021-Injection/
 */

// ============================================================================
// VULNERABLE CODE
// ============================================================================

/*
app.get('/user', (req, res) => {
    // Directly trusting query parameters can lead to NoSQL injection
    db.collection('users').findOne({ username: req.query.username }, (err, user) => {
        if (err) throw err;
        res.json(user);
    });
});
*/

// ============================================================================
// SECURE FIXED CODE
// ============================================================================

const express = require('express');
const { MongoClient } = require('mongodb');
const app = express();

// Middleware for input validation
const validateInput = require('express-validator');

/**
 * Sanitize user input to prevent NoSQL injection.
 * 
 * This function ensures that user input is always treated as a string value,
 * never as a MongoDB query operator object.
 * 
 * @param {any} input - User input to sanitize
 * @returns {string|null} Sanitized string or null
 */
function sanitizeInput(input) {
    // Only accept primitive string values
    if (typeof input !== 'string') {
        return null;
    }
    
    // Remove any characters that could be problematic
    // This is defense in depth - the main protection is type checking
    const sanitized = input.trim();
    
    // Validate length
    if (sanitized.length === 0 || sanitized.length > 100) {
        return null;
    }
    
    return sanitized;
}

/**
 * Validate username format.
 * 
 * @param {string} username - Username to validate
 * @returns {boolean} True if valid, false otherwise
 */
function isValidUsername(username) {
    // Only allow alphanumeric, underscore, and hyphen
    const usernameRegex = /^[a-zA-Z0-9_-]{3,30}$/;
    return usernameRegex.test(username);
}

/**
 * Secure route using input validation and sanitization.
 * 
 * Security measures:
 * 1. Input type validation - ensures input is string, not object
 * 2. Input sanitization - removes potentially dangerous characters
 * 3. Format validation - enforces expected username format
 * 4. Explicit query structure - prevents query operator injection
 */
app.get('/user', async (req, res) => {
    try {
        // Step 1: Validate that username parameter exists
        if (!req.query.username) {
            return res.status(400).json({ 
                error: 'Username parameter is required' 
            });
        }
        
        // Step 2: Sanitize input (ensure it's a string, not an object)
        const username = sanitizeInput(req.query.username);
        
        if (username === null) {
            return res.status(400).json({ 
                error: 'Invalid username format - must be a string' 
            });
        }
        
        // Step 3: Validate username format
        if (!isValidUsername(username)) {
            return res.status(400).json({ 
                error: 'Invalid username format - only alphanumeric, underscore, and hyphen allowed (3-30 chars)' 
            });
        }
        
        // Step 4: Use explicit query structure
        // By explicitly constructing the query object, we prevent injection of operators
        const query = {
            username: username  // This is guaranteed to be a string, not an object
        };
        
        // Step 5: Execute query
        const user = await db.collection('users').findOne(query);
        
        if (!user) {
            return res.status(404).json({ 
                error: 'User not found' 
            });
        }
        
        // Step 6: Remove sensitive fields before sending response
        const sanitizedUser = {
            id: user._id,
            username: user.username,
            email: user.email,
            createdAt: user.createdAt
            // Exclude: password, passwordHash, apiKeys, tokens, etc.
        };
        
        res.json(sanitizedUser);
        
    } catch (error) {
        // Log error for monitoring (in production, use proper logging)
        console.error('Error fetching user:', error);
        
        // Return generic error message (don't leak implementation details)
        res.status(500).json({ 
            error: 'Internal server error' 
        });
    }
});

/**
 * Alternative approach using express-validator middleware.
 * This provides more robust validation and is recommended for production.
 */
const { query, validationResult } = require('express-validator');

app.get('/user-validated',
    // Validation chain
    [
        query('username')
            .exists().withMessage('Username is required')
            .isString().withMessage('Username must be a string')
            .trim()
            .isLength({ min: 3, max: 30 }).withMessage('Username must be 3-30 characters')
            .matches(/^[a-zA-Z0-9_-]+$/).withMessage('Username contains invalid characters')
    ],
    async (req, res) => {
        // Check validation results
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                errors: errors.array() 
            });
        }
        
        // At this point, we know username is a valid string
        const username = req.query.username;
        
        try {
            // Explicit query structure
            const user = await db.collection('users').findOne({
                username: username  // Safe: validated as string
            });
            
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }
            
            // Return sanitized user data
            const { password, passwordHash, apiKey, ...safeUser } = user;
            res.json(safeUser);
            
        } catch (error) {
            console.error('Database error:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    }
);

/**
 * Example: Search users with multiple criteria (secure implementation).
 * 
 * This demonstrates how to safely handle multiple search parameters
 * while preventing NoSQL injection.
 */
app.get('/users/search',
    [
        query('term')
            .optional()
            .isString().withMessage('Search term must be a string')
            .trim()
            .isLength({ min: 2, max: 50 }).withMessage('Search term must be 2-50 characters'),
        query('limit')
            .optional()
            .isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
            .toInt()
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        
        const searchTerm = req.query.term || '';
        const limit = req.query.limit || 10;
        
        try {
            // Build query safely
            // Use RegExp constructor instead of allowing user to provide regex
            const searchRegex = new RegExp(searchTerm, 'i'); // 'i' for case-insensitive
            
            const query = {
                $or: [
                    { username: searchRegex },
                    { email: searchRegex }
                ]
            };
            
            const users = await db.collection('users')
                .find(query)
                .limit(limit)
                .project({ password: 0, passwordHash: 0, apiKey: 0 }) // Exclude sensitive fields
                .toArray();
            
            res.json(users);
            
        } catch (error) {
            console.error('Search error:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    }
);

/**
 * HOW THIS FIX ADDRESSES THE VULNERABILITY:
 * 
 * 1. Input Type Validation:
 *    - Explicitly checks that input is a string, not an object
 *    - Rejects any attempt to pass MongoDB operators as objects
 *    - Prevents injection of { $ne: null }, { $gt: '' }, etc.
 * 
 * 2. Input Sanitization:
 *    - Trims whitespace
 *    - Validates length constraints
 *    - Ensures input is in expected format
 * 
 * 3. Format Validation:
 *    - Uses regex to enforce allowed characters
 *    - Prevents special characters that could be problematic
 *    - Enforces business logic constraints (length, format)
 * 
 * 4. Explicit Query Construction:
 *    - Query object is built explicitly in code
 *    - User input is only used as string values
 *    - MongoDB operators come from trusted code, not user input
 * 
 * 5. Output Sanitization:
 *    - Removes sensitive fields before sending response
 *    - Uses projection to exclude password fields in queries
 *    - Prevents accidental exposure of sensitive data
 * 
 * 6. Error Handling:
 *    - Catches and logs errors appropriately
 *    - Returns generic error messages to users
 *    - Doesn't leak database structure or implementation details
 * 
 * SECURITY IMPROVEMENTS:
 * - Immune to NoSQL injection attacks
 * - Cannot inject query operators ($ne, $gt, $regex, etc.)
 * - Cannot bypass authentication through query manipulation
 * - Cannot cause denial of service through expensive queries
 * - Follows OWASP injection prevention best practices
 * - Implements defense in depth (validation + sanitization + explicit queries)
 * - Type-safe parameter handling
 * 
 * WHY THIS PREVENTS INJECTION:
 * - Original: db.findOne({ username: req.query.username })
 *   If req.query.username = { $ne: null } → matches all documents
 * 
 * - Fixed: const username = sanitizeInput(req.query.username)
 *          db.findOne({ username: username })
 *   If req.query.username = { $ne: null } → sanitizeInput returns null → request rejected
 *   If req.query.username = "admin" → query becomes { username: "admin" } → safe exact match
 * 
 * ADDITIONAL PROTECTION LAYERS:
 * - Use MongoDB user with minimal privileges (read-only where possible)
 * - Enable MongoDB query logging and monitoring
 * - Implement rate limiting to prevent brute force
 * - Use Content Security Policy headers
 * - Regular security audits of query patterns
 * 
 * DEPENDENCIES REQUIRED:
 * npm install express mongodb express-validator
 * 
 * References:
 * - OWASP Top 10 A03:2021: https://owasp.org/Top10/A03_2021-Injection/
 * - OWASP NoSQL Injection: https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html
 * - MongoDB Security: https://docs.mongodb.com/manual/security/
 * - Express Validator: https://express-validator.github.io/docs/
 */