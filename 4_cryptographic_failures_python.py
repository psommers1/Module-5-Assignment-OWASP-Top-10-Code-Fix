"""
OWASP Top 10 - Cryptographic Failures (Python)
Author: Paul Sommers

VULNERABILITY EXPLANATION:
This code uses SHA-1 for password hashing, which is fundamentally insecure for this purpose.
SHA-1 is vulnerable because:
1. It's designed to be fast, enabling rapid brute-force attacks
2. Cryptographically broken - collision attacks have been demonstrated
3. No salt is used, making rainbow table attacks trivial
4. No key stretching, so millions of passwords can be tested per second
5. Officially deprecated by NIST since 2011 for cryptographic use

Using SHA-1 for passwords allows attackers to easily crack password hashes using
modern hardware, rainbow tables, or pre-computed hash databases.

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

def hash_password_secure(password):
    """
    Securely hash a password using PBKDF2-HMAC-SHA256.
    
    PBKDF2 (Password-Based Key Derivation Function 2) is a key stretching
    algorithm designed to be computationally expensive, making brute-force
    attacks impractical. It applies a pseudorandom function (like HMAC-SHA256)
    multiple times to the password with a unique salt.
    
    Args:
        password (str): The plaintext password to hash
        
    Returns:
        str: A string containing the salt and hash, separated by '$'
             Format: "salt$hash" (both base64 encoded)
             
    Security features:
        - Unique salt for each password (prevents rainbow tables)
        - 100,000 iterations (configurable, slows down brute-force)
        - SHA-256 as underlying hash function (secure and widely supported)
        - 32-byte output length (256 bits of security)
    
    Reference: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    """
    if not password:
        raise ValueError("Password cannot be empty")
    
    # Generate a cryptographically secure random salt
    # 16 bytes (128 bits) is the OWASP recommended minimum
    salt = os.urandom(16)
    
    # PBKDF2 parameters
    iterations = 100000  # OWASP recommends minimum 100,000 for PBKDF2-SHA256
    hash_length = 32     # 32 bytes = 256 bits
    algorithm = 'sha256' # Use SHA-256 as the underlying hash
    
    # Perform key derivation
    # This applies HMAC-SHA256 100,000 times, making it very slow
    password_hash = hashlib.pbkdf2_hmac(
        algorithm,
        password.encode('utf-8'),
        salt,
        iterations,
        dklen=hash_length
    )
    
    # Store salt and hash together
    # Both are base64 encoded for safe storage in databases
    salt_b64 = b64encode(salt).decode('utf-8')
    hash_b64 = b64encode(password_hash).decode('utf-8')
    
    # Format: salt$hash (dollar sign as separator)
    return f"{salt_b64}${hash_b64}"


def verify_password(password, stored_hash):
    """
    Verify a password against a stored hash using constant-time comparison.
    
    Args:
        password (str): The plaintext password to verify
        stored_hash (str): The stored hash string (format: "salt$hash")
        
    Returns:
        bool: True if password matches, False otherwise
        
    Security features:
        - Constant-time comparison prevents timing attacks
        - Extracts salt from stored hash (no separate storage needed)
        - Recomputes hash using same parameters
    
    Reference: https://docs.python.org/3/library/secrets.html#secrets.compare_digest
    """
    if not password or not stored_hash:
        return False
    
    try:
        # Split stored hash into salt and hash components
        salt_b64, hash_b64 = stored_hash.split('$')
        salt = b64decode(salt_b64)
        expected_hash = b64decode(hash_b64)
        
        # Recompute hash with provided password and extracted salt
        iterations = 100000
        hash_length = 32
        algorithm = 'sha256'
        
        computed_hash = hashlib.pbkdf2_hmac(
            algorithm,
            password.encode('utf-8'),
            salt,
            iterations,
            dklen=hash_length
        )
        
        # Use constant-time comparison to prevent timing attacks
        # This is critical - normal comparison (==) leaks information via timing
        import secrets
        return secrets.compare_digest(computed_hash, expected_hash)
        
    except (ValueError, TypeError):
        # Handle malformed hash strings
        return False


# Alternative implementation using bcrypt (also recommended by OWASP)
"""
To use bcrypt, install with: pip install bcrypt

import bcrypt

def hash_password_bcrypt(password):
    '''
    Hash password using bcrypt with automatic salt generation.
    
    Bcrypt is specifically designed for password hashing and includes:
    - Automatic salt generation and management
    - Configurable work factor (cost parameter)
    - Resistance to GPU-based cracking
    
    Args:
        password (str): Plaintext password to hash
        
    Returns:
        str: Bcrypt hash (includes salt and cost factor)
    
    Reference: https://pypi.org/project/bcrypt/
    '''
    if not password:
        raise ValueError("Password cannot be empty")
    
    # Generate salt with work factor 12
    # Higher work factor = more secure but slower
    # 12 is good balance as of 2024
    salt = bcrypt.gensalt(rounds=12)
    
    # Hash password with salt
    password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
    
    # Return as string (bcrypt already includes salt in output)
    return password_hash.decode('utf-8')


def verify_password_bcrypt(password, stored_hash):
    '''
    Verify password against bcrypt hash.
    
    Args:
        password (str): Plaintext password to verify
        stored_hash (str): Stored bcrypt hash
        
    Returns:
        bool: True if password matches, False otherwise
    '''
    if not password or not stored_hash:
        return False
    
    try:
        # bcrypt.checkpw handles salt extraction and comparison
        return bcrypt.checkpw(
            password.encode('utf-8'),
            stored_hash.encode('utf-8')
        )
    except Exception:
        return False
"""


# Example usage demonstrating secure password handling
if __name__ == "__main__":
    # Example 1: User registration
    user_password = "MySecureP@ssw0rd123!"
    hashed = hash_password_secure(user_password)
    print(f"Stored hash: {hashed}")
    # Example output: "4KjX7Y9pQ3mL8wR2vH6n5A==$7xZq9W4kP2sL8mNv3CbR5tY6hJ9..."
    
    # Example 2: User login - correct password
    login_attempt = "MySecureP@ssw0rd123!"
    is_valid = verify_password(login_attempt, hashed)
    print(f"Correct password verification: {is_valid}")  # True
    
    # Example 3: User login - incorrect password
    wrong_password = "WrongPassword"
    is_invalid = verify_password(wrong_password, hashed)
    print(f"Wrong password verification: {is_invalid}")  # False
    
    # Example 4: Same password produces different hashes (due to random salt)
    hash1 = hash_password_secure(user_password)
    hash2 = hash_password_secure(user_password)
    print(f"\nSame password, different hashes:")
    print(f"Hash 1: {hash1}")
    print(f"Hash 2: {hash2}")
    print(f"Hashes are different: {hash1 != hash2}")  # True


"""
HOW THIS FIX ADDRESSES THE VULNERABILITY:

1. Secure Algorithm:
   - Replaced SHA-1 with PBKDF2-HMAC-SHA256
   - PBKDF2 is specifically designed for password derivation
   - SHA-256 is the underlying hash (still secure as of 2024)

2. Salt Generation:
   - Each password gets a unique cryptographically random salt
   - 16 bytes (128 bits) exceeds OWASP minimum recommendation
   - Salt is stored with the hash (no separate storage needed)
   - Prevents rainbow table and pre-computation attacks

3. Key Stretching:
   - 100,000 iterations makes brute-force computationally expensive
   - Takes ~100ms per hash (acceptable for logins, impractical for cracking)
   - Iteration count can be increased as hardware improves

4. Constant-Time Comparison:
   - Uses secrets.compare_digest() for verification
   - Prevents timing attacks that could leak password information
   - Critical security feature often overlooked

5. Proper Encoding:
   - Base64 encoding for safe database storage
   - UTF-8 encoding for password text
   - Handles special characters correctly

SECURITY IMPROVEMENTS:
- Passwords cannot be reversed from hash (one-way function)
- Rainbow tables rendered useless by unique salts
- Brute-force attacks are 100,000x slower than SHA-1
- Timing attacks prevented by constant-time comparison
- Follows OWASP password storage best practices
- Future-proof (can increase iterations over time)
- No external dependencies (uses Python standard library)

PERFORMANCE IMPACT:
- Hashing: ~100ms per password (acceptable for registration/password changes)
- Verification: ~100ms per attempt (acceptable for login)
- Intentional slowdown prevents brute-force attacks

ALTERNATIVE ALGORITHMS:
The code includes bcrypt as an alternative, which is also recommended by OWASP.
Argon2id is the current gold standard (as of 2024) if you need maximum security.

References:
- OWASP Top 10 A02:2021: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
- OWASP Password Storage: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- Python hashlib documentation: https://docs.python.org/3/library/hashlib.html
- Python secrets module: https://docs.python.org/3/library/secrets.html
- NIST SP 800-132: https://csrc.nist.gov/publications/detail/sp/800-132/final
"""