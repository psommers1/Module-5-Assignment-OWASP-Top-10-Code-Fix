/**
 * OWASP Top 10 - Cryptographic Failures (Java)
 * Author: Paul Sommers
 * 
 * VULNERABILITY EXPLANATION:
 * This code uses MD5 for password hashing, which is critically insecure. MD5 is:
 * 1. A fast hashing algorithm that enables brute-force attacks
 * 2. Vulnerable to collision attacks where different inputs produce same hash
 * 3. Not designed for password storage (no salt, no key stretching)
 * 4. Easily cracked using rainbow tables and modern GPUs
 * 
 * Attackers can quickly crack MD5 hashes, especially common passwords, leading
 * to account compromise and data breaches.
 * 
 * Reference: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
 */

// ============================================================================
// VULNERABLE CODE
// ============================================================================

/*
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.xml.bind.DatatypeConverter;

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
import java.security.SecureRandom;

/**
 * Secure password hashing implementation using BCrypt.
 * 
 * BCrypt is specifically designed for password hashing and includes:
 * - Automatic salt generation and storage
 * - Configurable work factor (computational cost)
 * - Resistance to rainbow table attacks
 * - Resistance to brute-force attacks through key stretching
 * 
 * Reference: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
 */
public class SecurePasswordHasher {
    
    // BCrypt strength parameter (work factor)
    // Higher values = more secure but slower
    // 12 is a good balance as of 2024
    private static final int BCRYPT_STRENGTH = 12;
    
    private final PasswordEncoder passwordEncoder;
    
    /**
     * Constructor initializes BCrypt password encoder with secure strength.
     * 
     * BCrypt automatically handles:
     * - Random salt generation for each password
     * - Multiple rounds of hashing (2^strength iterations)
     * - Storage of salt within the hash output
     */
    public SecurePasswordHasher() {
        this.passwordEncoder = new BCryptPasswordEncoder(BCRYPT_STRENGTH, new SecureRandom());
    }
    
    /**
     * Hash a password securely using BCrypt.
     * 
     * @param password The plaintext password to hash
     * @return A secure BCrypt hash string containing the salt and hash
     * @throws IllegalArgumentException if password is null or empty
     */
    public String hashPassword(String password) {
        // Input validation
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
        
        // BCrypt automatically:
        // 1. Generates a cryptographically secure random salt
        // 2. Applies the salt to the password
        // 3. Performs 2^BCRYPT_STRENGTH iterations of hashing
        // 4. Returns a string containing both salt and hash
        return passwordEncoder.encode(password);
    }
    
    /**
     * Verify a plaintext password against a stored BCrypt hash.
     * 
     * @param plainPassword The plaintext password provided by user
     * @param hashedPassword The stored BCrypt hash to verify against
     * @return true if password matches, false otherwise
     */
    public boolean verifyPassword(String plainPassword, String hashedPassword) {
        // Input validation
        if (plainPassword == null || hashedPassword == null) {
            return false;
        }
        
        // BCrypt.matches() is constant-time to prevent timing attacks
        return passwordEncoder.matches(plainPassword, hashedPassword);
    }
}

/**
 * Alternative implementation using Argon2id - the current gold standard
 * for password hashing (recommended by OWASP as of 2024).
 * 
 * Reference: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
 */
/*
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

public class Argon2PasswordHasher {
    
    // Argon2 parameters (OWASP recommendations)
    private static final int SALT_LENGTH = 16;      // 16 bytes
    private static final int HASH_LENGTH = 32;      // 32 bytes
    private static final int PARALLELISM = 1;       // Degree of parallelism
    private static final int MEMORY = 65536;        // Memory cost in KB (64 MB)
    private static final int ITERATIONS = 3;        // Time cost (iterations)
    
    private final PasswordEncoder passwordEncoder;
    
    public Argon2PasswordHasher() {
        this.passwordEncoder = new Argon2PasswordEncoder(
            SALT_LENGTH,
            HASH_LENGTH,
            PARALLELISM,
            MEMORY,
            ITERATIONS
        );
    }
    
    public String hashPassword(String password) {
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
        return passwordEncoder.encode(password);
    }
    
    public boolean verifyPassword(String plainPassword, String hashedPassword) {
        if (plainPassword == null || hashedPassword == null) {
            return false;
        }
        return passwordEncoder.matches(plainPassword, hashedPassword);
    }
}
*/

/**
 * Example usage demonstrating secure password handling.
 */
public class PasswordExample {
    public static void main(String[] args) {
        SecurePasswordHasher hasher = new SecurePasswordHasher();
        
        // Hash a new password during registration
        String userPassword = "MySecureP@ssw0rd!";
        String hashedPassword = hasher.hashPassword(userPassword);
        
        // Store hashedPassword in database (never store plaintext!)
        System.out.println("Stored hash: " + hashedPassword);
        // Example output: $2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgXYrC/0wZUcFyO7UCyKYRXYW6
        
        // Verify password during login
        String loginAttempt = "MySecureP@ssw0rd!";
        boolean isValid = hasher.verifyPassword(loginAttempt, hashedPassword);
        System.out.println("Password valid: " + isValid);  // true
        
        // Wrong password attempt
        String wrongPassword = "WrongPassword123";
        boolean isInvalid = hasher.verifyPassword(wrongPassword, hashedPassword);
        System.out.println("Wrong password valid: " + isInvalid);  // false
    }
}

/**
 * HOW THIS FIX ADDRESSES THE VULNERABILITY:
 * 
 * 1. Modern Hashing Algorithm:
 *    - Replaced MD5 with BCrypt, designed specifically for password hashing
 *    - BCrypt is computationally expensive, making brute-force attacks impractical
 *    - Resistant to rainbow table attacks due to per-password salts
 * 
 * 2. Automatic Salt Management:
 *    - BCrypt generates unique salt for each password automatically
 *    - Salt is stored as part of the hash output
 *    - Prevents pre-computation attacks
 * 
 * 3. Configurable Work Factor:
 *    - BCRYPT_STRENGTH parameter controls computational cost
 *    - Can be increased over time as hardware improves
 *    - Current setting (12) requires ~250ms per hash
 * 
 * 4. Constant-Time Comparison:
 *    - Password verification uses constant-time comparison
 *    - Prevents timing attacks that could leak password information
 * 
 * 5. Input Validation:
 *    - Validates passwords are not null or empty
 *    - Prevents null pointer exceptions and invalid states
 * 
 * SECURITY IMPROVEMENTS:
 * - Passwords cannot be reversed from hash (one-way function)
 * - Each password has unique salt, preventing rainbow table attacks
 * - Computational cost makes brute-force attacks impractical
 * - Follows current OWASP password storage best practices
 * - Future-proof with adjustable work factor
 * - Protection against timing attacks
 * 
 * DEPENDENCIES REQUIRED (Maven):
 * <dependency>
 *     <groupId>org.springframework.security</groupId>
 *     <artifactId>spring-security-crypto</artifactId>
 *     <version>6.1.0</version>
 * </dependency>
 * 
 * References:
 * - OWASP Top 10 A02:2021: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
 * - OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
 * - Spring Security Crypto: https://docs.spring.io/spring-security/reference/features/authentication/password-storage.html
 * - BCrypt specification: https://en.wikipedia.org/wiki/Bcrypt
 */