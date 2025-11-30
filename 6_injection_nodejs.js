/**
 * OWASP Top 10 - Injection (NoSQL Injection in Node.js)
 * Author: Paul Sommers
 * 
 * VULNERABILITY: Directly passes query parameters to MongoDB allowing object injection
 * RISK: Authentication bypass, data exfiltration, query operator injection
 * Reference: https://owasp.org/Top10/A03_2021-Injection/
 */

// ============================================================================
// VULNERABLE CODE
// ============================================================================
/*
app.get('/user', (req, res) => {
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
const app = express();

function sanitizeInput(input) {
    // Only accept string values, reject objects
    if (typeof input !== 'string') {
        return null;
    }
    return input.trim();
}

function isValidUsername(username) {
    // Only allow alphanumeric, underscore, hyphen (3-30 chars)
    return /^[a-zA-Z0-9_-]{3,30}$/.test(username);
}

app.get('/user', async (req, res) => {
    try {
        // Sanitize and validate input
        const username = sanitizeInput(req.query.username);
        
        if (!username || !isValidUsername(username)) {
            return res.status(400).json({ error: 'Invalid username' });
        }
        
        // Explicit query structure - username is guaranteed to be string
        const user = await db.collection('users').findOne({
            username: username  // Safe: string value, not operator object
        });
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Return only non-sensitive data
        const { password, passwordHash, ...safeUser } = user;
        res.json(safeUser);
        
    } catch (error) {
        res.status(500).json({ error: 'Internal error' });
    }
});

/**
 * HOW THE FIX WORKS:
 * - sanitizeInput() ensures input is string, not object (prevents {$ne: null})
 * - isValidUsername() validates format with regex
 * - Explicit query construction prevents operator injection
 * - Even if attacker sends {$ne: null}, it's rejected before reaching DB
 * 
 * Reference: https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html
 */