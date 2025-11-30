/**
 * OWASP Top 10 - Cryptographic Failures (Java)
 * Author: Paul Sommers
 * 
 * VULNERABILITY: Uses MD5 for password hashing
 * RISK: MD5 is fast and broken, allowing easy password cracking using rainbow tables
 * Reference: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
 */

// ============================================================================
// VULNERABLE CODE
// ============================================================================
/*
import java.security.MessageDigest;

public String hashPassword(String password) throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance("MD5");
    md.update(password.getBytes());
    byte[] digest = md.digest();
    return DatatypeConverter.printHexBinary(digest);
}
*/

// ============================================================================
// SECURE FIXED CODE
// ============================================================================

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class SecurePasswordHasher {
    
    private static final int BCRYPT_STRENGTH = 12;  // Work factor
    private final PasswordEncoder passwordEncoder;
    
    public SecurePasswordHasher() {
        this.passwordEncoder = new BCryptPasswordEncoder(BCRYPT_STRENGTH);
    }
    
    /**
     * Hash password using BCrypt
     */
    public String hashPassword(String password) {
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be empty");
        }
        // BCrypt automatically generates salt and applies 2^12 iterations
        return passwordEncoder.encode(password);
    }
    
    /**
     * Verify password against stored hash
     */
    public boolean verifyPassword(String plainPassword, String hashedPassword) {
        if (plainPassword == null || hashedPassword == null) {
            return false;
        }
        // Constant-time comparison prevents timing attacks
        return passwordEncoder.matches(plainPassword, hashedPassword);
    }
}

/**
 * HOW THE FIX WORKS:
 * - BCrypt is designed for password hashing (unlike MD5)
 * - Automatically generates unique salt per password
 * - Uses 2^12 = 4,096 iterations (slow by design)
 * - Prevents rainbow table attacks
 * - Constant-time comparison prevents timing attacks
 * 
 * Reference: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
 */