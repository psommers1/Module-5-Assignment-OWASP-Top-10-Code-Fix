/**
 * OWASP Top 10 - Injection (SQL Injection in Java)
 * Author: Paul Sommers
 * 
 * VULNERABILITY EXPLANATION:
 * This code constructs SQL queries by directly concatenating user input into the query string.
 * This is extremely dangerous because:
 * 1. Allows attackers to inject malicious SQL commands
 * 2. Enables data exfiltration (retrieving unauthorized data)
 * 3. Allows data modification or deletion
 * 4. Can lead to complete database compromise
 * 5. May enable authentication bypass
 * 
 * Example attack: If username = "admin' OR '1'='1", the query becomes:
 * SELECT * FROM users WHERE username = 'admin' OR '1'='1'
 * This returns all users because '1'='1' is always true.
 * 
 * More dangerous: username = "'; DROP TABLE users; --"
 * Would execute: SELECT * FROM users WHERE username = ''; DROP TABLE users; --'
 * This would delete the entire users table.
 * 
 * Reference: https://owasp.org/Top10/A03_2021-Injection/
 */

// ============================================================================
// VULNERABLE CODE
// ============================================================================

/*
import java.sql.*;

public class VulnerableUserQuery {
    public ResultSet getUserByUsername(Connection connection, HttpServletRequest request) 
            throws SQLException {
        String username = request.getParameter("username");
        
        // DANGEROUS: Direct string concatenation with user input
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        return rs;
    }
}
*/

// ============================================================================
// SECURE FIXED CODE
// ============================================================================

import java.sql.*;
import javax.servlet.http.HttpServletRequest;
import java.util.regex.Pattern;

/**
 * Secure implementation using PreparedStatement to prevent SQL injection.
 * 
 * PreparedStatements provide protection by:
 * - Separating SQL code from data
 * - Automatically escaping special characters
 * - Using parameterized queries
 * - Treating user input as data, never as SQL code
 * 
 * Reference: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
 */
public class SecureUserQuery {
    
    // Define allowed characters for username validation (defense in depth)
    private static final Pattern VALID_USERNAME = Pattern.compile("^[a-zA-Z0-9_-]{3,30}$");
    
    /**
     * Retrieve user by username using parameterized query.
     * 
     * @param connection Active database connection
     * @param request HTTP request containing username parameter
     * @return User data or null if not found
     * @throws SQLException If database error occurs
     * @throws IllegalArgumentException If username is invalid
     */
    public User getUserByUsername(Connection connection, HttpServletRequest request) 
            throws SQLException {
        
        // Step 1: Input validation (defense in depth)
        String username = request.getParameter("username");
        
        if (username == null || username.isEmpty()) {
            throw new IllegalArgumentException("Username parameter is required");
        }
        
        // Validate username format
        if (!VALID_USERNAME.matcher(username).matches()) {
            throw new IllegalArgumentException(
                "Invalid username format. Only alphanumeric, underscore, and hyphen allowed (3-30 chars)"
            );
        }
        
        // Step 2: Use PreparedStatement with parameterized query
        // The '?' placeholder is replaced with the parameter value safely
        String query = "SELECT id, username, email, created_at FROM users WHERE username = ?";
        
        try (PreparedStatement pstmt = connection.prepareStatement(query)) {
            // Step 3: Set parameter value
            // PreparedStatement automatically escapes special characters
            // and treats the value as data, not SQL code
            pstmt.setString(1, username);  // 1 = first parameter (?)
            
            // Step 4: Execute query
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    // Map result to User object
                    return mapResultSetToUser(rs);
                }
                return null;  // User not found
            }
        }
        // try-with-resources ensures automatic cleanup of resources
    }
    
    /**
     * Helper method to map ResultSet to User object.
     * 
     * @param rs ResultSet containing user data
     * @return User object with data from database
     */
    private User mapResultSetToUser(ResultSet rs) throws SQLException {
        User user = new User();
        user.setId(rs.getInt("id"));
        user.setUsername(rs.getString("username"));
        user.setEmail(rs.getString("email"));
        user.setCreatedAt(rs.getTimestamp("created_at"));
        // Note: Password hash is NOT retrieved for security
        return user;
    }
    
    /**
     * Example: Search users with multiple parameters.
     * Demonstrates using multiple placeholders in PreparedStatement.
     */
    public List<User> searchUsers(Connection connection, String searchTerm, int limit) 
            throws SQLException {
        
        // Input validation
        if (searchTerm == null || searchTerm.isEmpty()) {
            throw new IllegalArgumentException("Search term is required");
        }
        
        if (limit < 1 || limit > 100) {
            throw new IllegalArgumentException("Limit must be between 1 and 100");
        }
        
        // Parameterized query with multiple placeholders
        String query = "SELECT id, username, email FROM users " +
                      "WHERE username LIKE ? OR email LIKE ? " +
                      "LIMIT ?";
        
        List<User> users = new ArrayList<>();
        
        try (PreparedStatement pstmt = connection.prepareStatement(query)) {
            // Set all parameters
            String searchPattern = "%" + searchTerm + "%";
            pstmt.setString(1, searchPattern);  // First LIKE clause
            pstmt.setString(2, searchPattern);  // Second LIKE clause
            pstmt.setInt(3, limit);             // LIMIT value
            
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    users.add(mapResultSetToUser(rs));
                }
            }
        }
        
        return users;
    }
}

/**
 * Alternative approach using JPA/Hibernate (also secure).
 * 
 * JPA uses parameterized queries by default, providing built-in
 * protection against SQL injection.
 */
/*
import javax.persistence.*;

@Repository
public class UserRepository {
    
    @PersistenceContext
    private EntityManager entityManager;
    
    public User findByUsername(String username) {
        // JPA Named Parameter - automatically parameterized
        String jpql = "SELECT u FROM User u WHERE u.username = :username";
        
        try {
            return entityManager.createQuery(jpql, User.class)
                .setParameter("username", username)  // Safe parameterization
                .getSingleResult();
        } catch (NoResultException e) {
            return null;  // User not found
        }
    }
    
    // Using Criteria API (type-safe, parameterized by design)
    public List<User> searchUsersCriteria(String searchTerm, int limit) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<User> query = cb.createQuery(User.class);
        Root<User> user = query.from(User.class);
        
        // Build predicate (automatically parameterized)
        Predicate usernameLike = cb.like(user.get("username"), "%" + searchTerm + "%");
        Predicate emailLike = cb.like(user.get("email"), "%" + searchTerm + "%");
        
        query.where(cb.or(usernameLike, emailLike));
        
        return entityManager.createQuery(query)
            .setMaxResults(limit)
            .getResultList();
    }
}
*/

/**
 * User model class for examples.
 */
class User {
    private int id;
    private String username;
    private String email;
    private Timestamp createdAt;
    
    // Getters and setters
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    
    public Timestamp getCreatedAt() { return createdAt; }
    public void setCreatedAt(Timestamp createdAt) { this.createdAt = createdAt; }
}

/**
 * HOW THIS FIX ADDRESSES THE VULNERABILITY:
 * 
 * 1. PreparedStatement with Parameterization:
 *    - Separates SQL structure from data
 *    - User input is treated as data values, never as SQL code
 *    - Database driver handles all necessary escaping
 *    - Prevents injection of SQL commands
 * 
 * 2. Input Validation (Defense in Depth):
 *    - Validates username format using regex
 *    - Restricts allowed characters to alphanumeric, underscore, hyphen
 *    - Enforces length constraints (3-30 characters)
 *    - Rejects malicious patterns before they reach the database
 * 
 * 3. Resource Management:
 *    - Uses try-with-resources for automatic cleanup
 *    - Prevents resource leaks
 *    - Ensures connections and statements are properly closed
 * 
 * 4. Error Handling:
 *    - Provides clear error messages without leaking database structure
 *    - Throws appropriate exceptions for invalid input
 *    - Doesn't expose SQL errors to users
 * 
 * 5. Least Privilege:
 *    - SELECT query only retrieves necessary columns
 *    - Excludes sensitive data (password hashes)
 *    - Limits result set size to prevent resource exhaustion
 * 
 * SECURITY IMPROVEMENTS:
 * - Immune to SQL injection attacks
 * - Cannot execute unauthorized SQL commands
 * - Cannot access unauthorized data
 * - Cannot modify or delete database records via injection
 * - Follows OWASP SQL injection prevention best practices
 * - Implements defense in depth with validation + parameterization
 * - Type-safe parameter binding prevents type confusion attacks
 * 
 * WHY PREPARED STATEMENTS WORK:
 * When you use PreparedStatement:
 * 1. SQL structure is sent to database and compiled FIRST
 * 2. Parameters are sent SEPARATELY as data values
 * 3. Database knows the structure is fixed, parameters are just values
 * 4. Even if parameter contains SQL syntax, it's treated as literal text
 * 
 * Example:
 * - Vulnerable: "SELECT * FROM users WHERE username = '" + "admin' OR '1'='1" + "'"
 *   Result: WHERE username = 'admin' OR '1'='1' (OR executes as SQL!)
 * 
 * - Secure: PreparedStatement with parameter "admin' OR '1'='1"
 *   Result: WHERE username = 'admin'' OR ''1''=''1' (treated as literal string!)
 * 
 * ADDITIONAL PROTECTION LAYERS:
 * - Use database accounts with minimal privileges
 * - Enable query logging for security monitoring
 * - Implement rate limiting on queries
 * - Use Web Application Firewall (WAF) for additional detection
 * 
 * References:
 * - OWASP Top 10 A03:2021: https://owasp.org/Top10/A03_2021-Injection/
 * - OWASP SQL Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
 * - Java PreparedStatement: https://docs.oracle.com/javase/tutorial/jdbc/basics/prepared.html
 * - OWASP Query Parameterization: https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html
 */