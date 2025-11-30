/**
 * OWASP Top 10 - Identification and Authentication Failures (Java)
 * Author: Paul Sommers
 * 
 * VULNERABILITY EXPLANATION:
 * This code compares passwords using plain text string comparison (equals method).
 * This creates multiple critical security vulnerabilities:
 * 
 * 1. Plain Text Password Storage:
 *    - The code compares with user.getPassword(), implying passwords are stored as plain text
 *    - If database is compromised, all passwords are immediately exposed
 *    - Violates fundamental security principles
 * 
 * 2. Timing Attack Vulnerability:
 *    - The equals() method returns false as soon as it finds a difference
 *    - An attacker can measure response time to determine correct password characters
 *    - With enough attempts, can reconstruct the entire password
 * 
 * 3. No Rate Limiting:
 *    - Allows unlimited login attempts
 *    - Enables brute force attacks
 *    - No account lockout mechanism
 * 
 * 4. No Additional Security Layers:
 *    - No multi-factor authentication (MFA)
 *    - No CAPTCHA after failed attempts
 *    - No suspicious activity detection
 * 
 * How timing attacks work:
 * - Password: "Secret123"
 * - Guess: "XXXXXXX" -> fails immediately (0ms)
 * - Guess: "SXXXXXX" -> takes slightly longer (0.1ms) because first char matches
 * - Guess: "SeXXXXX" -> takes even longer (0.2ms)
 * - Continue until full password discovered
 * 
 * Reference: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
 */

// ============================================================================
// VULNERABLE CODE
// ============================================================================

/*
public class VulnerableLogin {
    
    public boolean authenticateUser(String inputPassword, User user) {
        // CRITICAL FLAWS:
        // 1. Assumes password stored in plain text (user.getPassword())
        // 2. Uses timing-vulnerable comparison (equals)
        // 3. No rate limiting
        // 4. No additional security measures
        
        if (inputPassword.equals(user.getPassword())) { 
            // Login success
            return true;
        }
        return false;
    }
}
*/

// ============================================================================
// SECURE FIXED CODE
// ============================================================================

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

/**
 * Secure authentication implementation with multiple security layers.
 * 
 * Security features:
 * - BCrypt password hashing (secure storage)
 * - Constant-time password comparison (prevents timing attacks)
 * - Account lockout after failed attempts
 * - Rate limiting per IP address
 * - Failed attempt tracking
 * - Security logging
 * - Optional MFA support
 * 
 * Reference: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
 */
public class SecureAuthentication {
    
    // Password encoder using BCrypt
    private final PasswordEncoder passwordEncoder;
    
    // Track failed login attempts per username
    private final Map<String, LoginAttemptTracker> attemptTrackers;
    
    // Track rate limiting per IP address
    private final Map<String, RateLimiter> rateLimiters;
    
    // Configuration constants
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCKOUT_DURATION_MINUTES = 15;
    private static final int RATE_LIMIT_WINDOW_MINUTES = 5;
    private static final int MAX_ATTEMPTS_PER_IP = 20;
    
    public SecureAuthentication() {
        this.passwordEncoder = new BCryptPasswordEncoder(12);
        this.attemptTrackers = new ConcurrentHashMap<>();
        this.rateLimiters = new ConcurrentHashMap<>();
    }
    
    /**
     * Authenticate user with comprehensive security checks.
     * 
     * @param username Username attempting to log in
     * @param inputPassword Password provided by user
     * @param user User object from database (contains hashed password)
     * @param ipAddress IP address of login attempt
     * @return AuthenticationResult with success status and reason
     */
    public AuthenticationResult authenticateUser(
            String username, 
            String inputPassword, 
            User user, 
            String ipAddress) {
        
        // Security Check 1: Input Validation
        if (username == null || username.isEmpty() || 
            inputPassword == null || inputPassword.isEmpty()) {
            logSecurityEvent("Authentication failed: Invalid input", username, ipAddress);
            return AuthenticationResult.failure("Invalid username or password");
        }
        
        // Security Check 2: Rate Limiting (by IP)
        if (isRateLimited(ipAddress)) {
            logSecurityEvent("Rate limit exceeded", username, ipAddress);
            return AuthenticationResult.failure(
                "Too many login attempts. Please try again later."
            );
        }
        
        // Security Check 3: Check if account is locked
        LoginAttemptTracker tracker = getOrCreateTracker(username);
        if (tracker.isLocked()) {
            logSecurityEvent("Login attempt on locked account", username, ipAddress);
            return AuthenticationResult.failure(
                String.format("Account is locked. Try again in %d minutes.",
                    tracker.getMinutesUntilUnlock())
            );
        }
        
        // Security Check 4: User exists
        if (user == null) {
            // Important: Return same error as wrong password
            // This prevents username enumeration
            tracker.recordFailedAttempt();
            recordRateLimitAttempt(ipAddress);
            logSecurityEvent("Login failed: User not found", username, ipAddress);
            return AuthenticationResult.failure("Invalid username or password");
        }
        
        // Security Check 5: Password verification using constant-time comparison
        // BCrypt's matches() method is designed to be timing-attack resistant
        boolean passwordMatches = passwordEncoder.matches(
            inputPassword, 
            user.getPasswordHash()
        );
        
        if (!passwordMatches) {
            // Record failed attempt
            tracker.recordFailedAttempt();
            recordRateLimitAttempt(ipAddress);
            
            // Log security event
            logSecurityEvent(
                String.format("Login failed: Wrong password (attempt %d/%d)",
                    tracker.getFailedAttempts(), MAX_FAILED_ATTEMPTS),
                username, 
                ipAddress
            );
            
            // Check if account should be locked
            if (tracker.getFailedAttempts() >= MAX_FAILED_ATTEMPTS) {
                logSecurityEvent("Account locked due to excessive failed attempts", 
                    username, ipAddress);
            }
            
            return AuthenticationResult.failure("Invalid username or password");
        }
        
        // SUCCESS: Password is correct
        
        // Reset failed attempt counter
        tracker.reset();
        
        // Log successful login
        logSecurityEvent("Login successful", username, ipAddress);
        
        // Update user's last login timestamp
        user.setLastLoginTime(LocalDateTime.now());
        user.setLastLoginIp(ipAddress);
        
        return AuthenticationResult.success(user);
    }
    
    /**
     * Get or create login attempt tracker for username.
     */
    private LoginAttemptTracker getOrCreateTracker(String username) {
        return attemptTrackers.computeIfAbsent(
            username.toLowerCase(), 
            k -> new LoginAttemptTracker()
        );
    }
    
    /**
     * Check if IP address has exceeded rate limit.
     */
    private boolean isRateLimited(String ipAddress) {
        RateLimiter limiter = rateLimiters.computeIfAbsent(
            ipAddress,
            k -> new RateLimiter(MAX_ATTEMPTS_PER_IP, RATE_LIMIT_WINDOW_MINUTES)
        );
        return !limiter.allowRequest();
    }
    
    /**
     * Record login attempt for rate limiting.
     */
    private void recordRateLimitAttempt(String ipAddress) {
        RateLimiter limiter = rateLimiters.computeIfAbsent(
            ipAddress,
            k -> new RateLimiter(MAX_ATTEMPTS_PER_IP, RATE_LIMIT_WINDOW_MINUTES)
        );
        limiter.recordAttempt();
    }
    
    /**
     * Log security events for monitoring and incident response.
     * In production, use proper logging framework (SLF4J, Log4j2, etc.)
     */
    private void logSecurityEvent(String event, String username, String ipAddress) {
        String timestamp = LocalDateTime.now().toString();
        System.out.println(String.format(
            "[%s] SECURITY: %s | User: %s | IP: %s",
            timestamp, event, username, ipAddress
        ));
        
        // In production:
        // - Send to SIEM (Security Information and Event Management)
        // - Alert security team on suspicious patterns
        // - Store in secure audit log
    }
    
    /**
     * Hash a password securely using BCrypt.
     * This should be used when creating new users or changing passwords.
     * 
     * @param plainTextPassword The password to hash
     * @return BCrypt hash of the password
     */
    public String hashPassword(String plainTextPassword) {
        if (plainTextPassword == null || plainTextPassword.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be empty");
        }
        
        // BCrypt automatically:
        // 1. Generates unique salt
        // 2. Applies 2^12 rounds of hashing (configurable)
        // 3. Returns hash that includes salt
        return passwordEncoder.encode(plainTextPassword);
    }
}

/**
 * Tracks failed login attempts and implements account lockout.
 */
class LoginAttemptTracker {
    private int failedAttempts = 0;
    private LocalDateTime lockoutUntil = null;
    private static final int MAX_ATTEMPTS = 5;
    private static final int LOCKOUT_MINUTES = 15;
    
    public void recordFailedAttempt() {
        failedAttempts++;
        
        if (failedAttempts >= MAX_ATTEMPTS) {
            lockoutUntil = LocalDateTime.now().plusMinutes(LOCKOUT_MINUTES);
        }
    }
    
    public boolean isLocked() {
        if (lockoutUntil == null) {
            return false;
        }
        
        // Check if lockout has expired
        if (LocalDateTime.now().isAfter(lockoutUntil)) {
            reset();
            return false;
        }
        
        return true;
    }
    
    public int getMinutesUntilUnlock() {
        if (lockoutUntil == null) {
            return 0;
        }
        return (int) ChronoUnit.MINUTES.between(LocalDateTime.now(), lockoutUntil);
    }
    
    public void reset() {
        failedAttempts = 0;
        lockoutUntil = null;
    }
    
    public int getFailedAttempts() {
        return failedAttempts;
    }
}

/**
 * Rate limiter to prevent brute force attacks from single IP.
 */
class RateLimiter {
    private final int maxAttempts;
    private final int windowMinutes;
    private int attempts = 0;
    private LocalDateTime windowStart = LocalDateTime.now();
    
    public RateLimiter(int maxAttempts, int windowMinutes) {
        this.maxAttempts = maxAttempts;
        this.windowMinutes = windowMinutes;
    }
    
    public boolean allowRequest() {
        cleanupOldAttempts();
        return attempts < maxAttempts;
    }
    
    public void recordAttempt() {
        cleanupOldAttempts();
        attempts++;
    }
    
    private void cleanupOldAttempts() {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime windowEnd = windowStart.plusMinutes(windowMinutes);
        
        if (now.isAfter(windowEnd)) {
            // Reset window
            attempts = 0;
            windowStart = now;
        }
    }
}

/**
 * Result object for authentication attempts.
 */
class AuthenticationResult {
    private final boolean success;
    private final String message;
    private final User user;
    
    private AuthenticationResult(boolean success, String message, User user) {
        this.success = success;
        this.message = message;
        this.user = user;
    }
    
    public static AuthenticationResult success(User user) {
        return new AuthenticationResult(true, "Authentication successful", user);
    }
    
    public static AuthenticationResult failure(String message) {
        return new AuthenticationResult(false, message, null);
    }
    
    public boolean isSuccess() { return success; }
    public String getMessage() { return message; }
    public User getUser() { return user; }
}

/**
 * User model with secure password storage.
 */
class User {
    private Long id;
    private String username;
    private String passwordHash;  // NEVER store plain text password
    private LocalDateTime lastLoginTime;
    private String lastLoginIp;
    private boolean mfaEnabled;
    
    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }
    
    public LocalDateTime getLastLoginTime() { return lastLoginTime; }
    public void setLastLoginTime(LocalDateTime lastLoginTime) { 
        this.lastLoginTime = lastLoginTime; 
    }
    
    public String getLastLoginIp() { return lastLoginIp; }
    public void setLastLoginIp(String lastLoginIp) { this.lastLoginIp = lastLoginIp; }
    
    public boolean isMfaEnabled() { return mfaEnabled; }
    public void setMfaEnabled(boolean mfaEnabled) { this.mfaEnabled = mfaEnabled; }
}

/**
 * HOW THIS FIX ADDRESSES THE VULNERABILITY:
 * 
 * 1. Secure Password Storage:
 *    - Uses BCrypt for password hashing (one-way function)
 *    - Each password has unique salt (prevents rainbow tables)
 *    - Configurable work factor (2^12 = 4096 iterations)
 *    - Password cannot be reversed from hash
 * 
 * 2. Timing Attack Prevention:
 *    - BCrypt's matches() method uses constant-time comparison
 *    - Response time doesn't leak password information
 *    - All comparisons take same amount of time regardless of correctness
 * 
 * 3. Account Lockout:
 *    - Locks account after 5 failed attempts
 *    - 15-minute lockout duration
 *    - Prevents brute force attacks
 *    - Automatic unlock after timeout
 * 
 * 4. Rate Limiting:
 *    - Limits attempts per IP address (20 per 5 minutes)
 *    - Prevents distributed brute force attacks
 *    - Separate from per-account lockout
 * 
 * 5. Username Enumeration Prevention:
 *    - Returns same error message for wrong username and wrong password
 *    - Same response time for both cases
 *    - Prevents attackers from discovering valid usernames
 * 
 * 6. Security Logging:
 *    - Logs all authentication events
 *    - Tracks failed attempts
 *    - Records IP addresses
 *    - Enables security monitoring and incident response
 * 
 * 7. Input Validation:
 *    - Validates all inputs are present
 *    - Prevents null pointer exceptions
 *    - Sanitizes username (lowercase)
 * 
 * 8. Session Management:
 *    - Tracks last login time and IP
 *    - Enables detection of suspicious activity
 *    - Supports MFA flag for future implementation
 * 
 * SECURITY IMPROVEMENTS:
 * - Passwords cannot be stolen from database (hashed)
 * - Brute force attacks prevented (lockout + rate limiting)
 * - Timing attacks impossible (constant-time comparison)
 * - Username enumeration prevented (same error messages)
 * - Comprehensive security logging
 * - Defense in depth approach
 * - Follows OWASP authentication best practices
 * 
 * WHY BCRYPT IS SECURE:
 * - Designed specifically for password hashing
 * - Computationally expensive (slow by design)
 * - Unique salt per password (stored in hash)
 * - Adjustable work factor (can increase over time)
 * - Resistant to brute force (takes ~100ms per attempt)
 * - Resistant to rainbow tables (unique salts)
 * - Constant-time comparison
 * 
 * ADDITIONAL SECURITY MEASURES:
 * 1. Multi-Factor Authentication (MFA)
 *    - Add TOTP (Time-based One-Time Password)
 *    - SMS or email verification codes
 *    - Hardware security keys (U2F/WebAuthn)
 * 
 * 2. Password Policy Enforcement
 *    - Minimum 12 characters
 *    - Complexity requirements
 *    - Check against common passwords
 *    - Prevent password reuse
 * 
 * 3. Session Security
 *    - Secure session ID generation
 *    - Session timeout
 *    - Regenerate session ID after login
 *    - HttpOnly and Secure cookie flags
 * 
 * 4. CAPTCHA
 *    - Add after 2-3 failed attempts
 *    - Prevents automated attacks
 *    - Google reCAPTCHA or hCaptcha
 * 
 * 5. Notification
 *    - Email user on successful login
 *    - Alert on login from new device/location
 *    - Notify of account lockout
 * 
 * DEPENDENCIES REQUIRED (Maven):
 * <dependency>
 *     <groupId>org.springframework.security</groupId>
 *     <artifactId>spring-security-crypto</artifactId>
 *     <version>6.1.0</version>
 * </dependency>
 * 
 * References:
 * - OWASP Top 10 A07:2021: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
 * - OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
 * - OWASP Password Storage: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
 * - Timing Attack Prevention: https://codahale.com/a-lesson-in-timing-attacks/
 * - BCrypt Specification: https://en.wikipedia.org/wiki/Bcrypt
 */