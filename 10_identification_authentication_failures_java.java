/**
 * OWASP Top 10 - Identification and Authentication Failures (Java)
 * Author: Paul Sommers
 * 
 * VULNERABILITY: Plain text password comparison with no rate limiting or lockout
 * RISK: Timing attacks, brute force attacks, password theft from database
 * Reference: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
 */

// ============================================================================
// VULNERABLE CODE
// ============================================================================
/*
if (inputPassword.equals(user.getPassword())) { 
    // Login success
}
*/

// ============================================================================
// SECURE FIXED CODE
// ============================================================================

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

class SecureAuthentication {
    
    private final PasswordEncoder passwordEncoder;
    private final Map<String, FailedAttempts> failedAttemptsMap;
    private static final int MAX_FAILED_ATTEMPTS = 5;
    
    public SecureAuthentication() {
        this.passwordEncoder = new BCryptPasswordEncoder(12);
        this.failedAttemptsMap = new ConcurrentHashMap<>();
    }
    
    public AuthResult authenticateUser(String username, String inputPassword, User user) {
        // Check if account is locked
        FailedAttempts attempts = failedAttemptsMap.getOrDefault(username, new FailedAttempts());
        if (attempts.isLocked()) {
            return AuthResult.failure("Account locked");
        }
        
        // Verify password using constant-time comparison
        boolean passwordMatches = passwordEncoder.matches(inputPassword, user.getPasswordHash());
        
        if (!passwordMatches) {
            attempts.increment();
            failedAttemptsMap.put(username, attempts);
            return AuthResult.failure("Invalid credentials");
        }
        
        // Success - reset failed attempts
        failedAttemptsMap.remove(username);
        return AuthResult.success(user);
    }
    
    public String hashPassword(String password) {
        return passwordEncoder.encode(password);
    }
}

class FailedAttempts {
    private int count = 0;
    private LocalDateTime lockUntil = null;
    
    public void increment() {
        count++;
        if (count >= 5) {
            lockUntil = LocalDateTime.now().plusMinutes(15);
        }
    }
    
    public boolean isLocked() {
        return lockUntil != null && LocalDateTime.now().isBefore(lockUntil);
    }
}

class AuthResult {
    private final boolean success;
    private final String message;
    private final User user;
    
    private AuthResult(boolean success, String message, User user) {
        this.success = success;
        this.message = message;
        this.user = user;
    }
    
    static AuthResult success(User user) {
        return new AuthResult(true, "Success", user);
    }
    
    static AuthResult failure(String message) {
        return new AuthResult(false, message, null);
    }
}

class User {
    private String passwordHash;
    public String getPasswordHash() { return passwordHash; }
}

/**
 * HOW THE FIX WORKS:
 * - BCrypt for secure password hashing (2^12 iterations)
 * - Constant-time comparison prevents timing attacks
 * - Account lockout after 5 failed attempts (15 minutes)
 * - Never store plain text passwords
 * 
 * Reference: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
 */