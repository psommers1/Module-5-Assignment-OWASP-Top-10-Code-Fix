/**
 * OWASP Top 10 - Broken Access Control (JavaScript/Node.js)
 * Author: Paul Sommers
 * 
 * VULNERABILITY EXPLANATION:
 * This code allows any user to access any other user's profile by simply changing
 * the userId parameter in the URL. There is no authentication or authorization check
 * to verify that the requesting user has permission to view the requested profile.
 * This is a critical security flaw that exposes sensitive user data.
 * 
 * Reference: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
 */

// ============================================================================
// VULNERABLE CODE
// ============================================================================

/*
app.get('/profile/:userId', (req, res) => {
    User.findById(req.params.userId, (err, user) => {
        if (err) return res.status(500).send(err);
        res.json(user);
    });
});
*/

// ============================================================================
// SECURE FIXED CODE
// ============================================================================

const express = require('express');
const app = express();

// Middleware to verify user is authenticated
// This would typically use sessions, JWT tokens, or similar
function requireAuth(req, res, next) {
    // Check if user is authenticated (e.g., valid session or JWT token)
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    next();
}

// Middleware to verify user has permission to access the requested resource
function requireOwnership(req, res, next) {
    // Verify that the authenticated user is the owner of the requested profile
    // Or has appropriate admin/elevated permissions
    if (req.session.userId !== req.params.userId && !req.session.isAdmin) {
        return res.status(403).json({ 
            error: 'Forbidden: You do not have permission to access this resource' 
        });
    }
    next();
}

// Fixed route with proper access control
app.get('/profile/:userId', requireAuth, requireOwnership, (req, res) => {
    User.findById(req.params.userId, (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Internal server error' });
        }
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Only return non-sensitive user information
        // Filter out password hashes and other sensitive fields
        const sanitizedUser = {
            id: user.id,
            username: user.username,
            email: user.email,
            // Exclude: password, passwordHash, securityQuestions, etc.
        };
        
        res.json(sanitizedUser);
    });
});

/**
 * HOW THIS FIX ADDRESSES THE VULNERABILITY:
 * 
 * 1. Authentication Check (requireAuth middleware):
 *    - Verifies that the user is logged in before allowing access
 *    - Returns 401 Unauthorized if no valid session exists
 * 
 * 2. Authorization Check (requireOwnership middleware):
 *    - Ensures the authenticated user is the owner of the requested profile
 *    - Allows admin users to access any profile (with proper admin flag)
 *    - Returns 403 Forbidden if user lacks permission
 * 
 * 3. Data Sanitization:
 *    - Only returns non-sensitive user information
 *    - Explicitly excludes password hashes and security-related fields
 * 
 * 4. Proper Error Handling:
 *    - Provides appropriate HTTP status codes
 *    - Doesn't leak sensitive information in error messages
 * 
 * SECURITY IMPROVEMENTS:
 * - Implements the principle of least privilege
 * - Provides defense in depth with multiple security layers
 * - Prevents unauthorized access to user data
 * - Follows OWASP recommendations for access control
 * 
 * Reference: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
 */