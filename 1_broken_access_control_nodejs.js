/**
 * OWASP Top 10 - Broken Access Control (Node.js)
 * Author: Paul Sommers
 * 
 * VULNERABILITY: Allows any user to access any profile by changing the userId in URL
 * RISK: Unauthorized data access, privacy violations, horizontal privilege escalation
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

// Authentication middleware - verify user is logged in
function requireAuth(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    next();
}

// Authorization middleware - verify user owns the resource
function requireOwnership(req, res, next) {
    if (req.session.userId !== req.params.userId && !req.session.isAdmin) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    next();
}

// Secure route with access control
app.get('/profile/:userId', requireAuth, requireOwnership, (req, res) => {
    User.findById(req.params.userId, (err, user) => {
        if (err) return res.status(500).json({ error: 'Internal error' });
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        // Return only non-sensitive data
        const sanitizedUser = {
            id: user.id,
            username: user.username,
            email: user.email
        };
        res.json(sanitizedUser);
    });
});

/**
 * HOW THE FIX WORKS:
 * 1. requireAuth ensures user is logged in (prevents anonymous access)
 * 2. requireOwnership ensures user can only access their own profile
 * 3. Data sanitization prevents exposing sensitive fields like passwords
 * 
 * SECURITY IMPROVEMENTS:
 * - Authentication prevents unauthorized access
 * - Authorization prevents horizontal privilege escalation
 * - Data filtering prevents sensitive data exposure
 */