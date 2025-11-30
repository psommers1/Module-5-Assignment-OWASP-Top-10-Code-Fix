"""
OWASP Top 10 - Cryptographic Failures (Python)
Author: Paul Sommers

VULNERABILITY: Uses SHA-1 for password hashing
RISK: SHA-1 is fast and broken, vulnerable to rainbow tables and brute force
Reference: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
"""

# ============================================================================
# VULNERABLE CODE
# ============================================================================
"""
import hashlib

def hash_password(password):
    return hashlib.sha1(password.encode()).hexdigest()
"""

# ============================================================================
# SECURE FIXED CODE
# ============================================================================

import hashlib
import os
from base64 import b64encode, b64decode
import secrets

def hash_password_secure(password):
    """Hash password using PBKDF2-HMAC-SHA256"""
    if not password:
        raise ValueError("Password cannot be empty")
    
    salt = os.urandom(16)  # 16-byte random salt
    
    # PBKDF2 with 100,000 iterations (OWASP recommendation)
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000,
        dklen=32
    )
    
    # Store as "salt$hash" format
    salt_b64 = b64encode(salt).decode('utf-8')
    hash_b64 = b64encode(password_hash).decode('utf-8')
    return f"{salt_b64}${hash_b64}"

def verify_password(password, stored_hash):
    """Verify password using constant-time comparison"""
    if not password or not stored_hash:
        return False
    
    try:
        salt_b64, hash_b64 = stored_hash.split('$')
        salt = b64decode(salt_b64)
        expected_hash = b64decode(hash_b64)
        
        # Recompute hash with stored salt
        computed_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000,
            dklen=32
        )
        
        # Constant-time comparison prevents timing attacks
        return secrets.compare_digest(computed_hash, expected_hash)
    except:
        return False

"""
HOW THE FIX WORKS:
- PBKDF2 applies 100,000 iterations making brute force impractical
- Unique salt per password prevents rainbow tables
- Constant-time comparison prevents timing attacks
- No external dependencies (Python stdlib)

Reference: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
"""