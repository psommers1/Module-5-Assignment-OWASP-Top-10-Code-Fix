# OWASP Top 10 Code Fix Assignment

**Author:** Paul Sommers  
**Course:** SDEV245 - Secure Software Development  
**GitHub:** https://github.com/psommers1/Module-5-Assignment-OWASP-Top-10-Code-Fix

## Overview

This repository contains fixes for all ten vulnerabilities in the OWASP Top 10 2021. Each vulnerability includes:
- Explanation of the security risk
- Vulnerable code example
- Secure fixed code with comments
- Explanation of how the fix works
- References to official OWASP documentation

---

## 1. Broken Access Control

**Files:** `1_broken_access_control_nodejs.js`, `2_broken_access_control_python.py`

**Vulnerability:** Allows any user to access any profile by changing the userId in URL.

**Risk:** Unauthorized data access, privacy violations, horizontal privilege escalation.

**Fix:** 
- Add authentication middleware to verify user is logged in
- Add authorization middleware to verify user owns the resource
- Sanitize output data to exclude sensitive fields

**Reference:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/

---

## 2. Cryptographic Failures

**Files:** `3_cryptographic_failures_java.java`, `4_cryptographic_failures_python.py`

**Vulnerability:** Uses MD5/SHA-1 for password hashing.

**Risk:** Fast algorithms enable brute force and rainbow table attacks. Passwords easily cracked if database compromised.

**Fix:**
- Java: Use BCrypt with work factor 12 (2^12 = 4,096 iterations)
- Python: Use PBKDF2-HMAC-SHA256 with 100,000 iterations
- Automatic salt generation per password
- Constant-time comparison prevents timing attacks

**Reference:** https://owasp.org/Top10/A02_2021-Cryptographic_Failures/

---

## 3. Injection

**Files:** `5_injection_java.java`, `6_injection_nodejs.js`

**Vulnerability:** Direct string concatenation or object passing of user input to queries.

**Risk:** SQL/NoSQL injection allows attackers to steal data, bypass authentication, modify/delete records.

**Fix:**
- Java SQL: Use PreparedStatement with parameterized queries
- Node.js NoSQL: Validate input is string (not object), use explicit query structure
- Input validation with regex patterns

**Reference:** https://owasp.org/Top10/A03_2021-Injection/

---

## 4. Insecure Design

**File:** `7_insecure_design_python.py`

**Vulnerability:** Password reset with no identity verification or security controls.

**Risk:** Account takeover, unauthorized password changes, no user notification.

**Fix:**
- Cryptographically secure token sent via email
- Token expires in 1 hour
- One-time use tokens
- Rate limiting (3 requests/hour)
- Always return same message to prevent email enumeration
- Secure password hashing

**Reference:** https://owasp.org/Top10/A04_2021-Insecure_Design/

---

## 5. Software and Data Integrity Failures

**File:** `8_software_data_integrity_failures.html`

**Vulnerability:** Loading external JavaScript without integrity verification.

**Risk:** Supply chain attacks, CDN compromise, MITM attacks, malware injection.

**Fix:**
- Subresource Integrity (SRI) with cryptographic hash verification
- Content Security Policy (CSP) to whitelist approved sources
- Self-hosting critical libraries
- Version pinning (never use 'latest')

**Reference:** https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/

---

## 6. Server-Side Request Forgery (SSRF)

**File:** `9_ssrf_python.py`

**Vulnerability:** Accepts user URL and makes server-side request without validation.

**Risk:** Access internal networks, steal cloud metadata credentials, bypass firewalls, port scanning.

**Fix:**
- Validate URL scheme (only http/https)
- Block private IP ranges and localhost
- Resolve DNS and validate all IPs
- Restrict to ports 80 and 443
- Disable redirects to prevent DNS rebinding

**Reference:** https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/

---

## 7. Identification and Authentication Failures

**File:** `10_identification_authentication_failures_java.java`

**Vulnerability:** Plain text password comparison with no rate limiting.

**Risk:** Timing attacks, brute force, password theft from database.

**Fix:**
- BCrypt for secure password hashing
- Constant-time comparison prevents timing attacks
- Account lockout after 5 failed attempts (15 minutes)
- Never store plain text passwords

**Reference:** https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/

---

## Installation

**Python:**
```bash
pip install -r requirements.txt
```

**Java:**
```xml
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-crypto</artifactId>
    <version>6.1.0</version>
</dependency>
```

**Node.js:**
```bash
npm install express mongodb express-validator
```

---

## Key OWASP References

- OWASP Top 10 2021: https://owasp.org/Top10/
- Authorization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- SQL Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- SSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

---

## License

Educational purposes for SDEV245 coursework.