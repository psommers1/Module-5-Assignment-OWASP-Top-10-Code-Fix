# OWASP Top 10 Code Fix Assignment

**Author:** Paul Sommers  
**Course:** SDEV245 - Secure Software Development  
**Assignment:** Module 5 - OWASP Top 10 Code Fix  

## Overview

This repository contains fixes for all ten vulnerabilities in the OWASP Top 10 2021. Each vulnerability is addressed with:
- Detailed explanation of the security risk
- Analysis of the vulnerable code
- Secure code implementation with comprehensive security controls
- Explanation of how the fix mitigates the vulnerability
- References to official OWASP documentation

## Table of Contents

1. [Broken Access Control](#1-broken-access-control)
2. [Cryptographic Failures](#2-cryptographic-failures)
3. [Injection](#3-injection)
4. [Insecure Design](#4-insecure-design)
5. [Software and Data Integrity Failures](#5-software-and-data-integrity-failures)
6. [Server-Side Request Forgery (SSRF)](#6-server-side-request-forgery-ssrf)
7. [Identification and Authentication Failures](#7-identification-and-authentication-failures)
8. [References](#references)

---

## 1. Broken Access Control

### Files
- [`1_broken_access_control_nodejs.js`](1_broken_access_control_nodejs.js) - Node.js/Express implementation
- [`2_broken_access_control_python.py`](2_broken_access_control_python.py) - Python/Flask implementation

### Vulnerability #1 (Node.js)

**Vulnerable Code:**
```javascript
app.get('/profile/:userId', (req, res) => {
    User.findById(req.params.userId, (err, user) => {
        if (err) return res.status(500).send(err);
        res.json(user);
    });
});
```

**Security Risk Explanation:**

This code allows any user to access any other user's profile by simply changing the `userId` parameter in the URL. There is no authentication or authorization check to verify that the requesting user has permission to view the requested profile. This is a critical security flaw because:

1. **No Authentication Check:** The code doesn't verify if the user is logged in
2. **No Authorization Check:** Even if authenticated, it doesn't verify ownership of the profile
3. **Horizontal Privilege Escalation:** Users can access other users' data at the same privilege level
4. **Data Exposure:** Sensitive user information is exposed to unauthorized parties
5. **Enumeration Risk:** Attackers can enumerate all user profiles by iterating through user IDs

**Real-world Impact:**
- Unauthorized access to personal information
- Privacy violations and regulatory non-compliance (GDPR, CCPA)
- Potential identity theft
- Loss of customer trust and reputation damage

**Secure Implementation:**

The fix implements multiple security layers:

1. **Authentication Middleware (`requireAuth`):**
   - Verifies user has valid session before accessing any profile
   - Returns 401 Unauthorized if no session exists
   - Prevents anonymous access to user data

2. **Authorization Middleware (`requireOwnership`):**
   - Verifies authenticated user is the owner of the requested profile
   - Allows admin users to access any profile (with proper admin flag)
   - Returns 403 Forbidden if user lacks permission
   - Implements principle of least privilege

3. **Data Sanitization:**
   - Only returns non-sensitive user information
   - Explicitly excludes password hashes, security questions, tokens
   - Prevents accidental exposure of sensitive data

4. **Proper Error Handling:**
   - Provides appropriate HTTP status codes (401, 403, 404, 500)
   - Doesn't leak sensitive information in error messages
   - Generic errors prevent system enumeration

**How the Fix Works:**

The secure code uses middleware chaining to enforce security:
```javascript
app.get('/profile/:userId', requireAuth, requireOwnership, (req, res) => {
    // Only executes if both middleware checks pass
});
```

When a request comes in:
1. `requireAuth` verifies user is logged in → if not, return 401
2. `requireOwnership` verifies user owns the profile → if not, return 403
3. Only then does the handler execute and return sanitized data

**Security Improvements:**
- Implements defense in depth with multiple security layers
- Follows principle of least privilege
- Prevents unauthorized access to user data
- Complies with OWASP access control best practices
- Provides proper separation of authentication and authorization

**Reference:** [OWASP Top 10 A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

### Vulnerability #2 (Python)

**Vulnerable Code:**
```python
@app.route('/account/<user_id>')
def get_account(user_id):
    user = db.query(User).filter_by(id=user_id).first()
    return jsonify(user.to_dict())
```

**Security Risk Explanation:**

Similar to the Node.js example, this Python/Flask code exposes account information to anyone who can guess or enumerate user IDs. The risks include:

1. **No Access Control:** Anyone can access any user's account data
2. **Data Breach Potential:** Complete exposure of user database
3. **Account Enumeration:** Attackers can discover all valid user IDs
4. **Regulatory Violations:** Violates data protection regulations
5. **Trust Erosion:** Customers lose confidence in platform security

**Secure Implementation:**

The fix uses Python decorators to implement layered security:

1. **`@login_required` Decorator:**
   - Checks for valid user session
   - Returns 401 if not authenticated
   - Uses Flask session management

2. **`@check_account_ownership` Decorator:**
   - Verifies user is accessing their own account
   - Supports role-based access for admins
   - Returns 403 for unauthorized access

3. **Data Sanitization:**
   - Creates explicit whitelist of allowed fields
   - Excludes password hashes, API keys, tokens
   - Only returns necessary information

4. **Rate Limiting:**
   - Uses Flask-Limiter to prevent brute force
   - Limits to 10 requests per minute per route
   - Prevents rapid account enumeration

**How the Fix Works:**

Decorators are applied in order (bottom to top):
```python
@app.route('/account/<user_id>')
@limiter.limit("10 per minute")
@login_required
@check_account_ownership
def get_account(user_id):
    # Executes only if all checks pass
```

**Security Improvements:**
- Multiple layers of defense
- Proper authentication and authorization separation
- Rate limiting prevents automated attacks
- Data minimization principle applied
- Compliant with OWASP recommendations

**Reference:** [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

---

## 2. Cryptographic Failures

### Files
- [`3_cryptographic_failures_java.java`](3_cryptographic_failures_java.java) - Java implementation
- [`4_cryptographic_failures_python.py`](4_cryptographic_failures_python.py) - Python implementation

### Vulnerability #3 (Java - MD5)

**Vulnerable Code:**
```java
public String hashPassword(String password) throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance("MD5");
    md.update(password.getBytes());
    byte[] digest = md.digest();
    return DatatypeConverter.printHexBinary(digest);
}
```

**Security Risk Explanation:**

Using MD5 for password hashing is critically insecure for multiple reasons:

1. **Speed is a Weakness:** MD5 is designed to be fast, allowing attackers to test billions of passwords per second using GPUs
2. **Cryptographically Broken:** MD5 has known collision vulnerabilities where different inputs produce the same hash
3. **No Salt:** Without unique salts, identical passwords produce identical hashes, enabling rainbow table attacks
4. **No Key Stretching:** Single-round hashing makes brute force attacks trivial
5. **Deprecated:** NIST deprecated MD5 for cryptographic use in 2011

**Attack Scenarios:**

If a database is compromised with MD5 hashes:
- Common passwords cracked in seconds using rainbow tables
- Entire database of hashes can be cracked using modern GPUs in hours/days
- Attackers can pre-compute hashes for common passwords
- Dictionary attacks are highly effective

**Secure Implementation:**

The fix uses BCrypt, specifically designed for password hashing:

1. **BCrypt Algorithm:**
   - Adaptive function - computational cost can be increased over time
   - Built-in salt generation (unique per password)
   - Key stretching with configurable work factor
   - Resistant to rainbow table attacks

2. **Automatic Salt Management:**
   - BCrypt generates cryptographically secure random salt
   - Salt stored within the hash output (no separate storage needed)
   - Each password gets unique salt

3. **Configurable Work Factor:**
   - Set to 12 (2^12 = 4,096 iterations)
   - Can be increased as hardware improves
   - Current setting takes ~250ms per hash (acceptable for login, impractical for cracking)

4. **Constant-Time Comparison:**
   - `passwordEncoder.matches()` uses timing-safe comparison
   - Prevents timing attacks
   - Same execution time regardless of password correctness

**How the Fix Works:**

During registration:
```java
String hashedPassword = passwordEncoder.encode(userPassword);
// Store hashedPassword in database
```

BCrypt automatically:
1. Generates random salt (16 bytes)
2. Combines salt with password
3. Applies 4,096 rounds of hashing
4. Returns string containing salt + hash

During login:
```java
boolean isValid = passwordEncoder.matches(inputPassword, storedHash);
```

BCrypt:
1. Extracts salt from stored hash
2. Applies same process to input password
3. Compares using constant-time algorithm
4. Returns true/false

**Security Improvements:**
- Passwords cannot be reversed from hash
- Rainbow tables rendered useless by unique salts
- Brute force attacks 4,096x slower than MD5
- Future-proof with adjustable work factor
- Industry-standard secure password storage

**Reference:** [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

### Vulnerability #4 (Python - SHA-1)

**Vulnerable Code:**
```python
import hashlib

def hash_password(password):
    return hashlib.sha1(password.encode()).hexdigest()
```

**Security Risk Explanation:**

SHA-1 for password hashing is fundamentally insecure:

1. **Designed for Speed:** SHA-1 can compute millions of hashes per second on modern hardware
2. **Cryptographically Broken:** Google demonstrated collision attacks in 2017
3. **No Salt:** Identical passwords produce identical hashes
4. **Rainbow Tables:** Pre-computed hash databases make cracking trivial
5. **GPU Cracking:** Modern GPUs can crack billions of SHA-1 hashes per second

**Real-world Impact:**
- LinkedIn breach (2012): 6.5 million SHA-1 hashes cracked in days
- eHarmony breach (2012): 1.5 million SHA-1 passwords compromised
- Last.fm breach (2012): Passwords stored in SHA-1 easily cracked

**Secure Implementation:**

The fix uses PBKDF2-HMAC-SHA256, a key derivation function designed for passwords:

1. **PBKDF2 Algorithm:**
   - Password-Based Key Derivation Function 2
   - Applies hash function multiple times (100,000 iterations)
   - Makes brute force computationally expensive
   - NIST-approved for password-based key generation

2. **Automatic Salt Generation:**
   - Uses `os.urandom(16)` for cryptographically secure random bytes
   - 16 bytes (128 bits) of entropy per password
   - Salt stored with hash (format: `salt$hash`)

3. **High Iteration Count:**
   - 100,000 iterations (OWASP minimum for PBKDF2-SHA256)
   - Takes ~100ms per hash
   - Acceptable for authentication, impractical for cracking
   - Can be increased as hardware improves

4. **Constant-Time Comparison:**
   - Uses `secrets.compare_digest()` for verification
   - Prevents timing attacks
   - Critical security feature often overlooked

**How the Fix Works:**

Hashing (registration):
```python
def hash_password_secure(password):
    salt = os.urandom(16)  # Random 16-byte salt
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',           # Hash algorithm
        password.encode(),  # Password bytes
        salt,               # Unique salt
        100000,            # 100,000 iterations
        dklen=32           # 32-byte output
    )
    # Return as "salt$hash" format (both base64 encoded)
    return f"{b64encode(salt).decode()}${b64encode(password_hash).decode()}"
```

Verification (login):
```python
def verify_password(password, stored_hash):
    salt_b64, hash_b64 = stored_hash.split('$')
    salt = b64decode(salt_b64)
    expected_hash = b64decode(hash_b64)
    
    # Recompute hash with same parameters
    computed_hash = hashlib.pbkdf2_hmac(
        'sha256', password.encode(), salt, 100000, dklen=32
    )
    
    # Constant-time comparison prevents timing attacks
    return secrets.compare_digest(computed_hash, expected_hash)
```

**Security Improvements:**
- 100,000x slower than SHA-1 for attackers
- Unique salts prevent rainbow tables
- Timing attack resistant
- No external dependencies (Python stdlib)
- NIST-approved algorithm
- OWASP-compliant implementation

**Alternative:** The code also includes bcrypt implementation as a comment, which is equally secure and may be preferred in some contexts.

**Reference:** [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

---

## 3. Injection

### Files
- [`5_injection_java.java`](5_injection_java.java) - Java SQL Injection
- [`6_injection_nodejs.js`](6_injection_nodejs.js) - Node.js NoSQL Injection

### Vulnerability #5 (Java - SQL Injection)

**Vulnerable Code:**
```java
String username = request.getParameter("username");
String query = "SELECT * FROM users WHERE username = '" + username + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

**Security Risk Explanation:**

This code constructs SQL queries by directly concatenating user input, creating one of the most dangerous vulnerabilities in web applications:

1. **SQL Command Injection:** Attackers can inject arbitrary SQL commands
2. **Data Exfiltration:** Entire database can be dumped
3. **Data Modification:** Records can be modified or deleted
4. **Authentication Bypass:** Can log in as any user without password
5. **Privilege Escalation:** Can potentially gain database admin access

**Attack Examples:**

Authentication bypass:
```
Input: admin' OR '1'='1
Query becomes: SELECT * FROM users WHERE username = 'admin' OR '1'='1'
Result: Returns all users (OR condition always true)
```

Data destruction:
```
Input: '; DROP TABLE users; --
Query becomes: SELECT * FROM users WHERE username = ''; DROP TABLE users; --'
Result: Deletes entire users table
```

Data exfiltration (UNION attack):
```
Input: ' UNION SELECT credit_card, ssn FROM customers --
Query becomes: SELECT * FROM users WHERE username = '' UNION SELECT credit_card, ssn FROM customers --'
Result: Retrieves sensitive customer data
```

**Real-world Examples:**
- Heartland Payment Systems breach (2008): 130 million credit cards stolen via SQL injection
- TalkTalk breach (2015): 157,000 customers affected, £400,000 fine
- Sony Pictures breach (2011): 1 million accounts compromised

**Secure Implementation:**

The fix uses PreparedStatement with parameterized queries:

1. **PreparedStatement:**
   - Separates SQL structure from data
   - Treats user input as data values, never as SQL code
   - Database driver handles all escaping automatically

2. **Input Validation (Defense in Depth):**
   - Validates username format using regex
   - Restricts to alphanumeric, underscore, hyphen
   - Enforces length constraints (3-30 characters)
   - Rejects malicious patterns before database access

3. **Resource Management:**
   - Uses try-with-resources for automatic cleanup
   - Prevents resource leaks
   - Ensures proper connection handling

4. **Least Privilege:**
   - SELECT statement only retrieves necessary columns
   - Excludes sensitive data (password hashes)
   - Limits potential damage if vulnerability exists

**How the Fix Works:**

```java
String query = "SELECT id, username, email FROM users WHERE username = ?";

try (PreparedStatement pstmt = connection.prepareStatement(query)) {
    // Set parameter value - automatically escaped
    pstmt.setString(1, username);  // 1 = first parameter (?)
    
    try (ResultSet rs = pstmt.executeQuery()) {
        // Process results
    }
}
```

Process:
1. SQL structure sent to database and compiled FIRST
2. Parameters sent SEPARATELY as data values
3. Database knows structure is fixed, parameters are just values
4. Even if parameter contains SQL syntax, treated as literal text

Example:
- Malicious input: `admin' OR '1'='1`
- PreparedStatement treats as: `username = 'admin'' OR ''1''=''1'`
- Single quotes are escaped, entire string treated as literal username
- No SQL injection possible

**Security Improvements:**
- Immune to SQL injection attacks
- Cannot execute unauthorized SQL commands
- Cannot access unauthorized data
- Cannot modify or delete database records
- Type-safe parameter binding
- Defence in depth with validation + parameterization

**Reference:** [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

### Vulnerability #6 (Node.js - NoSQL Injection)

**Vulnerable Code:**
```javascript
app.get('/user', (req, res) => {
    db.collection('users').findOne({ username: req.query.username }, (err, user) => {
        if (err) throw err;
        res.json(user);
    });
});
```

**Security Risk Explanation:**

This code directly passes query parameters to MongoDB, enabling NoSQL injection attacks:

1. **Object Injection:** Attackers can send objects instead of strings
2. **Operator Injection:** Can inject MongoDB operators ($gt, $ne, $regex)
3. **Authentication Bypass:** Can retrieve any user's data
4. **Enumeration:** Can discover user information
5. **DoS:** Can create expensive queries

**Attack Examples:**

Retrieve any user (bypass filters):
```
URL: /user?username[$ne]=null
Sends: { username: { $ne: null } }
Result: Returns first user where username != null (matches all users)
```

Username enumeration:
```
URL: /user?username[$regex]=^admin
Sends: { username: { $regex: '^admin' } }
Result: Finds usernames starting with 'admin'
```

**Secure Implementation:**

The fix implements multiple security layers:

1. **Input Type Validation:**
   - Explicitly checks input is string, not object
   - Rejects attempts to pass MongoDB operators
   - Prevents `{ $ne: null }` style attacks

2. **Input Sanitization:**
   - `sanitizeInput()` function ensures string type
   - Removes potentially dangerous characters
   - Validates length constraints

3. **Format Validation:**
   - Regex validates allowed characters
   - Enforces business logic constraints
   - Only alphanumeric, underscore, hyphen allowed (3-30 chars)

4. **Explicit Query Construction:**
   - Query object built explicitly in code
   - User input only used as string values
   - MongoDB operators come from trusted code

**How the Fix Works:**

```javascript
function sanitizeInput(input) {
    // Only accept primitive string values
    if (typeof input !== 'string') {
        return null;  // Reject objects, arrays, etc.
    }
    return input.trim();
}

app.get('/user', async (req, res) => {
    const username = sanitizeInput(req.query.username);
    
    if (username === null || !isValidUsername(username)) {
        return res.status(400).json({ error: 'Invalid input' });
    }
    
    // Explicit query - username is guaranteed to be string
    const user = await db.collection('users').findOne({
        username: username  // Safe: string value, not operator object
    });
});
```

Why this prevents injection:
- Original vulnerable: `{ username: req.query.username }`
  - If `req.query.username = { $ne: null }` → matches all documents
- Fixed secure: `{ username: sanitizedString }`
  - If input is `{ $ne: null }` → `sanitizeInput()` returns null → request rejected
  - If input is `"admin"` → query becomes `{ username: "admin" }` → safe exact match

**Security Improvements:**
- Immune to NoSQL injection attacks
- Cannot inject query operators
- Cannot bypass authentication
- Type-safe parameter handling
- express-validator option for production use
- Rate limiting prevents brute force

**Reference:** [OWASP Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

---

## 4. Insecure Design

### File
- [`7_insecure_design_python.py`](7_insecure_design_python.py) - Python/Flask password reset

**Vulnerable Code:**
```python
@app.route('/reset-password', methods=['POST'])
def reset_password():
    email = request.form['email']
    new_password = request.form['new_password']
    user = User.query.filter_by(email=email).first()
    user.password = new_password
    db.session.commit()
    return 'Password reset'
```

**Security Risk Explanation:**

This password reset implementation has fundamental design flaws that cannot be fixed with simple code changes:

1. **No Identity Verification:** Anyone can reset any user's password with just an email address
2. **No Authentication:** Unauthenticated users can perform password resets
3. **No User Notification:** Legitimate user isn't notified of password change
4. **No Rate Limiting:** Allows automated attacks against multiple accounts
5. **Plain Text Storage:** Stores password directly (no hashing)
6. **No Token/Link:** Just email verification, easily guessable

**Attack Scenarios:**

Account takeover:
```
POST /reset-password
email=victim@example.com&new_password=hacked123

Result: Attacker now controls victim's account
```

Mass account compromise:
```python
for email in leaked_email_list:
    requests.post('/reset-password', data={
        'email': email,
        'new_password': 'compromised'
    })
```

**Why This is "Insecure Design":**

Unlike implementation bugs, this is a fundamental architectural flaw:
- No secure workflow designed
- Missing critical security controls
- Violates security principles
- Cannot be fixed with input validation alone
- Requires complete redesign

**Secure Implementation:**

The fix implements a complete secure password reset workflow:

1. **Secure Token Generation:**
   - Cryptographically secure random tokens (`secrets.token_hex(32)`)
   - 32 bytes (256 bits of entropy)
   - One-time use only
   - Time-limited (1 hour expiration)

2. **Identity Verification:**
   - Token sent only to registered email address
   - User must have access to email account
   - Cannot reset without email access

3. **Account Enumeration Prevention:**
   - Always returns same message regardless of email existence
   - Same response time for valid/invalid emails
   - Prevents discovering which emails are registered

4. **Rate Limiting:**
   - 3 password reset requests per hour per IP
   - 5 password resets per hour per IP
   - Prevents brute force and automated attacks
   - Prevents denial of service

5. **Password Security:**
   - Validates password strength (12+ chars, complexity)
   - Checks against common passwords
   - Uses secure hashing (PBKDF2-SHA256)
   - Never stores plain text

6. **Token Security:**
   - Tokens hashed before storage (prevents theft if DB compromised)
   - Single-use tokens (marked as used after reset)
   - Expiration enforced (1 hour validity)
   - Old unused tokens deleted

7. **User Notification:**
   - Email sent when reset requested
   - Confirmation email when password changed
   - User alerted if unauthorized change
   - Provides audit trail

8. **Session Management:**
   - Optional invalidation of all sessions after reset
   - Forces re-login with new password
   - Prevents attackers maintaining access

**Secure Workflow:**

Request reset:
```python
@app.route('/request-password-reset', methods=['POST'])
@limiter.limit("3 per hour")
def request_password_reset():
    email = request.get_json().get('email')
    user = User.query.filter_by(email=email).first()
    
    # Always return success (prevent enumeration)
    if user:
        token = generate_secure_token()
        send_reset_email(user.email, token)
    
    return jsonify({'message': 'If account exists, reset link sent'})
```

Complete reset:
```python
@app.route('/reset-password', methods=['POST'])
@limiter.limit("5 per hour")
def reset_password():
    token = request.get_json().get('token')
    new_password = request.get_json().get('new_password')
    
    # Validate token
    reset_request = find_valid_token(token)
    if not reset_request or is_expired(reset_request):
        return jsonify({'error': 'Invalid or expired token'}), 400
    
    # Validate password strength
    if not is_strong_password(new_password):
        return jsonify({'error': 'Password too weak'}), 400
    
    # Update password securely
    user.password_hash = hash_password(new_password)
    reset_request.used = True
    db.session.commit()
    
    # Notify user
    send_password_changed_email(user.email)
    
    return jsonify({'message': 'Password reset successful'})
```

**Security Improvements:**
- Requires proof of email ownership
- Prevents unauthorized password changes
- Protects against brute force
- Prevents account enumeration
- Notifies users of security events
- Defense in depth
- Secure by design

**Design Principles Followed:**
- Principle of least privilege
- Defense in depth
- Fail securely
- Complete mediation
- Psychological acceptability

**Reference:** [OWASP Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)

---

## 5. Software and Data Integrity Failures

### File
- [`8_software_data_integrity_failures.html`](8_software_data_integrity_failures.html) - HTML/JavaScript CDN security

**Vulnerable Code:**
```html
<script src="https://cdn.example.com/lib.js"></script>
```

**Security Risk Explanation:**

Loading JavaScript from external CDNs without integrity verification creates critical vulnerabilities:

1. **Supply Chain Attack:** If CDN is compromised, malicious code executes on your site
2. **Man-in-the-Middle (MITM):** Attackers can intercept and modify scripts in transit
3. **CDN Compromise:** CDN provider itself could be hacked
4. **DNS Hijacking:** Attackers redirect cdn.example.com to malicious server
5. **No Version Control:** Script at URL could change at any time

**Real-world Examples:**

British Airways breach (2018):
- Attackers modified Modernizr script loaded from third-party
- Injected credit card skimmer
- Stole 380,000 payment cards
- £20 million fine from ICO

Magecart attacks:
- Target third-party JavaScript on e-commerce sites
- Inject skimmers to steal credit cards
- Hundreds of sites compromised
- Billions in fraud

Event-Stream npm incident (2018):
- Popular npm package compromised
- Malicious code injected to steal cryptocurrency
- Downloaded 2 million times before discovery

**Attack Capabilities:**

If attacker compromises CDN or performs MITM:
- Steal user credentials and session tokens
- Inject malware or cryptocurrency miners
- Redirect users to phishing sites
- Steal sensitive data (credit cards, personal info)
- Deface the website
- Distribute ransomware

**Secure Implementation:**

The fix implements multiple security layers:

1. **Subresource Integrity (SRI):**
   - Cryptographic hash verifies resource integrity
   - Browser computes hash of downloaded file
   - Compares to integrity attribute
   - Blocks execution if mismatch

```html
<script 
    src="https://code.jquery.com/jquery-3.6.0.min.js"
    integrity="sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdPfGK"
    crossorigin="anonymous">
</script>
```

2. **Content Security Policy (CSP):**
   - Whitelist-based approach to allowed resources
   - Blocks unauthorized scripts
   - Prevents inline scripts (XSS protection)
   - Monitors and reports violations

```html
<meta http-equiv="Content-Security-Policy" content="
    default-src 'self';
    script-src 'self' https://code.jquery.com;
    style-src 'self' https://fonts.googleapis.com;
">
```

3. **Version Pinning:**
   - Use specific version numbers (never 'latest')
   - Prevents unexpected updates
   - Allows security review before updating
   - Reproducible builds

```html
<!-- BAD: Could change at any time -->
<script src="https://cdn.example.com/lib/latest.js"></script>

<!-- GOOD: Specific version + SRI -->
<script src="https://cdn.example.com/lib/1.2.3.min.js"
        integrity="sha384-HASH" crossorigin="anonymous"></script>
```

4. **CORS Configuration:**
   - `crossorigin="anonymous"` enables SRI
   - Allows browser to verify integrity
   - Prevents credential leakage to CDNs

5. **Self-Hosting (Best Practice):**
   - Host critical libraries on own infrastructure
   - Complete control over code
   - Better privacy (no CDN tracking)
   - Works when CDNs unavailable
   - No external dependencies

**How SRI Works:**

Generate hash:
```bash
# Download the exact version
wget https://code.jquery.com/jquery-3.6.0.min.js

# Generate SHA-384 hash
openssl dgst -sha384 -binary jquery-3.6.0.min.js | openssl base64 -A
```

Browser verification:
1. Downloads script from CDN
2. Computes SHA-384 hash of downloaded content
3. Compares computed hash with integrity attribute
4. If match: Executes script
5. If mismatch: Blocks script and reports error

**Why This Prevents Attacks:**

Without SRI:
- Attacker compromises CDN
- Modifies lib.js to inject malware
- All sites using that CDN now serve malware
- No detection until damage done

With SRI:
- Attacker compromises CDN and modifies lib.js
- Browser downloads modified lib.js
- Hash doesn't match integrity attribute
- Browser refuses to execute script
- Attack prevented

**CSP Directive Explanation:**

```
default-src 'self'
```
- Default: only load resources from same origin

```
script-src 'self' https://code.jquery.com
```
- Scripts from own domain and jQuery CDN only
- Blocks inline scripts (XSS protection)

```
frame-ancestors 'none'
```
- Prevents page embedding (clickjacking protection)

**Security Improvements:**
- Immune to CDN compromise (verified with SRI)
- Protected against MITM attacks
- Cannot load unauthorized scripts (CSP)
- Predictable behavior (version pinning)
- Reduced attack surface
- Better privacy
- Monitoring capabilities

**Tools for Implementation:**

Generate SRI hashes:
```bash
# Command line
wget https://example.com/lib.js
openssl dgst -sha384 -binary lib.js | openssl base64 -A
```

Online tools:
- https://www.srihash.org/
- https://report-uri.com/home/sri_hash

**Reference:** [OWASP Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)

---

## 6. Server-Side Request Forgery (SSRF)

### File
- [`9_ssrf_python.py`](9_ssrf_python.py) - Python SSRF protection

**Vulnerable Code:**
```python
import requests

url = input("Enter URL: ")
response = requests.get(url)
print(response.text)
```

**Security Risk Explanation:**

Accepting URLs from users and making server-side requests creates severe security vulnerabilities:

1. **Internal Network Access:** Access systems not exposed to internet
   - Internal APIs, databases, admin panels
   - Localhost services (127.0.0.1)
   - Private IP ranges (192.168.x.x, 10.x.x.x)

2. **Cloud Metadata Exploitation:** Steal cloud credentials
   - AWS: `http://169.254.169.254/latest/meta-data/`
   - Azure: `http://169.254.169.254/metadata/instance`
   - GCP: `http://metadata.google.internal/computeMetadata/v1/`

3. **Port Scanning:** Map internal network
   - Discover internal services
   - Identify vulnerable systems
   - Bypass firewall from trusted server IP

4. **Local File Access:** Read sensitive files
   - `file:///etc/passwd`
   - Configuration files
   - SSH keys, credentials

5. **Bypassing Access Controls:**
   - Server's IP likely whitelisted
   - Access resources that trust server
   - Bypass firewall rules

**Real-world Examples:**

Capital One breach (2019):
- SSRF vulnerability in web application
- Accessed AWS metadata endpoint
- Stole IAM credentials from metadata
- Used credentials to access S3 buckets
- 100 million customer records stolen
- $80 million fine

Uber breach (2016):
- SSRF to access internal GitHub
- Retrieved AWS credentials
- Accessed user database
- 57 million users affected

**Attack Examples:**

Access AWS metadata:
```
Input: http://169.254.169.254/latest/meta-data/iam/security-credentials/
Result: Retrieves AWS IAM credentials
Impact: Full AWS account compromise
```

Access internal admin panel:
```
Input: http://localhost:8080/admin
Result: Access admin panel bypassing firewall
Impact: Administrative access without authentication
```

Port scanning:
```python
for port in range(1, 1000):
    try:
        requests.get(f'http://internal-server:{port}', timeout=1)
        print(f'Port {port} is open')
    except:
        pass
```

**Secure Implementation:**

The fix implements comprehensive SSRF protection:

1. **URL Scheme Validation:**
   - Only allows http and https
   - Blocks file://, gopher://, dict://, ftp://
   - Prevents local file access
   - Stops protocol smuggling

2. **IP Address Validation:**
   - Blocks all private IP ranges (RFC 1918)
   - Blocks loopback (127.0.0.0/8, ::1)
   - Blocks link-local (169.254.0.0/16) - AWS metadata!
   - Blocks multicast and reserved addresses
   - Validates IPv4 and IPv6

3. **DNS Resolution Check:**
   - Resolves hostname before making request
   - Validates ALL resolved IPs are public
   - Prevents DNS rebinding attacks

4. **Port Restriction:**
   - Only allows ports 80 (HTTP) and 443 (HTTPS)
   - Blocks SSH (22), databases, internal services
   - Prevents access to non-web services

5. **Redirect Protection:**
   - Disables automatic redirect following
   - Prevents DNS rebinding via redirects
   - Stops redirect to file:// protocol

6. **Whitelist Enforcement:**
   - Optional domain whitelist
   - Only allows approved domains
   - Positive security model

7. **Resource Protection:**
   - Request timeout (prevents resource exhaustion)
   - Response size limit (prevents memory exhaustion)
   - Streaming response validation

**How the Fix Works:**

```python
class SSRFProtection:
    PRIVATE_IP_RANGES = [
        ipaddress.ip_network('127.0.0.0/8'),      # Loopback
        ipaddress.ip_network('10.0.0.0/8'),       # Private Class A
        ipaddress.ip_network('172.16.0.0/12'),    # Private Class B
        ipaddress.ip_network('192.168.0.0/16'),   # Private Class C
        ipaddress.ip_network('169.254.0.0/16'),   # Link-local (AWS!)
    ]
    
    @staticmethod
    def validate_url(url, whitelist=None):
        parsed = urlparse(url)
        
        # Check 1: Validate scheme
        if parsed.scheme not in ['http', 'https']:
            return False, "Invalid scheme"
        
        # Check 2: Reject credentials in URL
        if parsed.username or parsed.password:
            return False, "Credentials not allowed"
        
        # Check 3: Resolve and validate IP
        addr_info = socket.getaddrinfo(parsed.hostname, None)
        for info in addr_info:
            ip_str = info[4][0]
            if SSRFProtection.is_private_ip(ip_str):
                return False, f"Private IP: {ip_str}"
        
        # Check 4: Validate port
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        if port not in [80, 443]:
            return False, "Port not allowed"
        
        # Check 5: Whitelist (if provided)
        if whitelist and parsed.hostname not in whitelist:
            return False, "Not in whitelist"
        
        return True, "Valid"
```

Safe request:
```python
def fetch_url_safely(url, timeout=5, max_size=10*1024*1024):
    # Validate URL first
    is_valid, error = SSRFProtection.validate_url(url)
    if not is_valid:
        return {'success': False, 'error': error}
    
    # Make request with safety controls
    response = requests.get(
        url,
        timeout=timeout,
        allow_redirects=False,  # Critical: prevents DNS rebinding
        stream=True
    )
    
    # Check size before reading
    # Read with size limit
    # Return safely
```

**Why This Prevents SSRF:**

Attempt to access AWS metadata:
```
url = "http://169.254.169.254/latest/meta-data/"
is_valid, error = validate_url(url)
# Returns: (False, "URL resolves to private IP address: 169.254.169.254")
```

Attempt to access localhost:
```
url = "http://localhost:8080/admin"
is_valid, error = validate_url(url)
# Returns: (False, "Access to localhost is not allowed")
```

Attempt to access internal network:
```
url = "http://192.168.1.1/router"
is_valid, error = validate_url(url)
# Returns: (False, "URL resolves to private IP address: 192.168.1.1")
```

**Security Improvements:**
- Cannot access internal network resources
- Cannot read cloud metadata endpoints
- Cannot access localhost or loopback
- Cannot use non-HTTP protocols
- Cannot bypass via DNS rebinding
- Cannot access arbitrary ports
- Defense in depth
- OWASP-compliant

**Additional Protection Layers:**

Network segmentation:
- Run application in isolated network
- Restrict egress traffic
- Use network firewall rules

Monitoring:
- Log all outbound requests
- Alert on suspicious patterns
- Rate limiting on requests

Least privilege:
- Minimal network permissions
- Whitelist necessary domains only

**Reference:** [OWASP Server-Side Request Forgery Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

---

## 7. Identification and Authentication Failures

### File
- [`10_identification_authentication_failures_java.java`](10_identification_authentication_failures_java.java) - Java authentication

**Vulnerable Code:**
```java
if (inputPassword.equals(user.getPassword())) { 
    // Login success
}
```

**Security Risk Explanation:**

This simple password comparison has multiple critical flaws:

1. **Plain Text Password Storage:**
   - Implies passwords stored as plain text (`user.getPassword()`)
   - If database compromised, all passwords immediately exposed
   - Violates fundamental security principles
   - Regulatory violations (GDPR, PCI-DSS)

2. **Timing Attack Vulnerability:**
   - `equals()` returns false immediately upon finding difference
   - Attackers measure response time to determine correct characters
   - Can reconstruct entire password through timing analysis

3. **No Rate Limiting:**
   - Allows unlimited login attempts
   - Enables brute force attacks
   - No account lockout

4. **No Additional Security:**
   - No multi-factor authentication
   - No CAPTCHA after failures
   - No suspicious activity detection

**Timing Attack Explained:**

Password: "Secret123"

Attempts with response times:
- "XXXXXXX" → 0.1ms (fails at first char)
- "SXXXXXX" → 0.2ms (first char matches, fails at second)
- "SeXXXXX" → 0.3ms (two chars match, fails at third)
- Continue until full password discovered

Modern implementations can detect microsecond differences.

**Real-world Impact:**
- LinkedIn breach (2012): 6.5 million passwords in plain text
- Adobe breach (2013): 150 million accounts, encrypted poorly
- Yahoo breach (2014): 500 million accounts
- Equifax breach (2017): 147 million records

**Secure Implementation:**

The fix implements comprehensive authentication security:

1. **Secure Password Storage:**
   - BCrypt password hashing
   - Unique salt per password
   - 2^12 iterations (4,096 rounds)
   - Password cannot be reversed

```java
// Registration
String hashedPassword = passwordEncoder.encode(password);
user.setPasswordHash(hashedPassword);
```

2. **Constant-Time Comparison:**
   - BCrypt's `matches()` is timing-attack resistant
   - Same execution time regardless of correctness
   - Prevents password character discovery

```java
// Login
boolean matches = passwordEncoder.matches(inputPassword, user.getPasswordHash());
```

3. **Account Lockout:**
   - Locks after 5 failed attempts
   - 15-minute lockout duration
   - Prevents brute force
   - Automatic unlock

4. **Rate Limiting:**
   - 20 attempts per IP in 5 minutes
   - Prevents distributed attacks
   - Separate from account lockout

5. **Username Enumeration Prevention:**
   - Same error for wrong username and password
   - Same response time for both
   - Prevents discovering valid usernames

6. **Security Logging:**
   - Logs all authentication events
   - Tracks failed attempts
   - Records IP addresses
   - Enables monitoring and incident response

7. **Input Validation:**
   - Validates inputs present
   - Prevents null pointer exceptions
   - Sanitizes username

8. **Session Management:**
   - Tracks last login time and IP
   - Detects suspicious activity
   - Supports future MFA

**Authentication Flow:**

```java
public AuthenticationResult authenticateUser(
    String username, String inputPassword, User user, String ipAddress) {
    
    // 1. Input validation
    if (username == null || inputPassword == null) {
        return AuthenticationResult.failure("Invalid input");
    }
    
    // 2. Rate limiting (by IP)
    if (isRateLimited(ipAddress)) {
        return AuthenticationResult.failure("Too many attempts");
    }
    
    // 3. Account lockout check
    LoginAttemptTracker tracker = getOrCreateTracker(username);
    if (tracker.isLocked()) {
        return AuthenticationResult.failure("Account locked");
    }
    
    // 4. User exists check
    if (user == null) {
        tracker.recordFailedAttempt();
        return AuthenticationResult.failure("Invalid username or password");
    }
    
    // 5. Password verification (constant-time)
    boolean passwordMatches = passwordEncoder.matches(
        inputPassword, user.getPasswordHash()
    );
    
    if (!passwordMatches) {
        tracker.recordFailedAttempt();
        logSecurityEvent("Login failed", username, ipAddress);
        return AuthenticationResult.failure("Invalid username or password");
    }
    
    // SUCCESS
    tracker.reset();
    logSecurityEvent("Login successful", username, ipAddress);
    return AuthenticationResult.success(user);
}
```

**Why BCrypt is Secure:**

Hash generation:
```java
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
String hash = encoder.encode("password123");
// Output: $2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgXYrC/0wZUcFyO7UCyKYRXYW6
```

BCrypt hash components:
- `$2a$` = BCrypt algorithm identifier
- `12` = Cost factor (2^12 = 4,096 rounds)
- Next 22 chars = Salt (base64 encoded)
- Remaining = Hash of password + salt

Features:
1. **Unique Salt:** Random per password (prevents rainbow tables)
2. **Work Factor:** 4,096 rounds makes it slow (~100ms)
3. **Adaptive:** Can increase work factor as hardware improves
4. **Self-Contained:** Salt stored in hash string

**Security Improvements:**
- Passwords cannot be stolen (hashed)
- Brute force prevented (lockout + rate limiting)
- Timing attacks impossible (constant-time)
- Username enumeration prevented
- Comprehensive logging
- Defense in depth
- OWASP-compliant

**Additional Security Measures:**

Multi-Factor Authentication (MFA):
```java
// After password verification
if (user.isMfaEnabled()) {
    return AuthenticationResult.requireMfa();
}
```

Password policy:
```java
- Minimum 12 characters
- Mixed case, numbers, symbols
- Not in common password list
- No password reuse
```

Session security:
```java
// After successful login
- Generate secure session ID
- Set HttpOnly and Secure flags
- Implement session timeout
- Regenerate ID after login
```

**Reference:** [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

---

## References

### OWASP Official Documentation

1. **OWASP Top 10 2021**
   - Main Page: https://owasp.org/Top10/
   - A01: Broken Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
   - A02: Cryptographic Failures: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
   - A03: Injection: https://owasp.org/Top10/A03_2021-Injection/
   - A04: Insecure Design: https://owasp.org/Top10/A04_2021-Insecure_Design/
   - A08: Software and Data Integrity Failures: https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
   - A10: Server-Side Request Forgery: https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
   - A07: Identification and Authentication Failures: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/

2. **OWASP Cheat Sheets**
   - Authorization: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
   - Password Storage: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
   - SQL Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
   - Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html
   - Authentication: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
   - Forgot Password: https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
   - SSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
   - Third Party JavaScript: https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html

3. **Additional OWASP Resources**
   - Query Parameterization: https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html
   - Session Management: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

### Official Framework Documentation

1. **Spring Security**
   - Password Storage: https://docs.spring.io/spring-security/reference/features/authentication/password-storage.html
   - BCrypt: https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/crypto/bcrypt/BCryptPasswordEncoder.html

2. **Flask**
   - Security Considerations: https://flask.palletsprojects.com/en/2.3.x/security/
   - View Decorators: https://flask.palletsprojects.com/en/2.3.x/patterns/viewdecorators/

3. **Express.js**
   - Security Best Practices: https://expressjs.com/en/advanced/best-practice-security.html

4. **Python**
   - hashlib: https://docs.python.org/3/library/hashlib.html
   - secrets module: https://docs.python.org/3/library/secrets.html

5. **MongoDB**
   - Security Checklist: https://docs.mongodb.com/manual/security/

6. **Java**
   - PreparedStatement: https://docs.oracle.com/javase/tutorial/jdbc/basics/prepared.html

### Standards and Specifications

1. **NIST Standards**
   - SP 800-132 (Password-Based Key Derivation): https://csrc.nist.gov/publications/detail/sp/800-132/final
   - SP 800-63B (Digital Identity Guidelines): https://pages.nist.gov/800-63-3/sp800-63b.html

2. **W3C Specifications**
   - Subresource Integrity: https://www.w3.org/TR/SRI/
   - Content Security Policy: https://www.w3.org/TR/CSP3/

3. **MDN Web Docs**
   - Subresource Integrity: https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
   - Content Security Policy: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

### Tools and Utilities

1. **SRI Hash Generators**
   - SRIHash.org: https://www.srihash.org/
   - Report URI: https://report-uri.com/home/sri_hash

2. **Security Testing**
   - OWASP ZAP: https://www.zaproxy.org/
   - Burp Suite: https://portswigger.net/burp

---

## Installation and Usage

### Prerequisites

**Python implementations:**
```bash
pip install flask flask-limiter werkzeug requests
```

**Java implementations:**
```xml
<!-- Maven dependencies -->
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-crypto</artifactId>
    <version>6.1.0</version>
</dependency>
```

**Node.js implementations:**
```bash
npm install express mongodb express-validator
```

### Running the Examples

Each code file contains example usage and demonstrations. To run:

**Python files:**
```bash
python 4_cryptographic_failures_python.py
python 9_ssrf_python.py
```

**Java files:**
Compile and run using your IDE or:
```bash
javac 3_cryptographic_failures_java.java
java 3_cryptographic_failures_java
```

**HTML files:**
Open in a modern web browser that supports SRI and CSP.

---

## Key Takeaways

1. **Defense in Depth:** Multiple security layers provide better protection than single controls
2. **Secure by Design:** Security must be built into the architecture, not added later
3. **Never Trust User Input:** Always validate, sanitize, and verify all user-provided data
4. **Use Proven Libraries:** Don't implement cryptography yourself, use established libraries
5. **Principle of Least Privilege:** Only grant the minimum necessary permissions
6. **Fail Securely:** Errors should not compromise security
7. **Keep Security Updated:** Regular reviews and updates are essential

---

## Author

**Paul Sommers**  
GitHub: [@psommers1](https://github.com/psommers1)  
Course: SDEV245 - Secure Software Development

## License

This code is provided for educational purposes as part of SDEV245 coursework.