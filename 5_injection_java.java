/**
 * OWASP Top 10 - Injection (SQL Injection in Java)
 * Author: Paul Sommers
 * 
 * VULNERABILITY: String concatenation with user input in SQL query
 * RISK: Attackers can inject SQL commands, steal/modify data, bypass authentication
 * Reference: https://owasp.org/Top10/A03_2021-Injection/
 */

// ============================================================================
// VULNERABLE CODE
// ============================================================================
/*
String username = request.getParameter("username");
String query = "SELECT * FROM users WHERE username = '" + username + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
*/

// ============================================================================
// SECURE FIXED CODE
// ============================================================================

import java.sql.*;

public class SecureUserQuery {
    
    public User getUserByUsername(Connection connection, String username) 
            throws SQLException {
        
        // Input validation
        if (username == null || username.isEmpty()) {
            throw new IllegalArgumentException("Username is required");
        }
        
        // Use PreparedStatement with parameterized query
        String query = "SELECT id, username, email FROM users WHERE username = ?";
        
        try (PreparedStatement pstmt = connection.prepareStatement(query)) {
            // Set parameter - automatically escaped by database
            pstmt.setString(1, username);
            
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    User user = new User();
                    user.setId(rs.getInt("id"));
                    user.setUsername(rs.getString("username"));
                    user.setEmail(rs.getString("email"));
                    return user;
                }
                return null;
            }
        }
    }
}

class User {
    private int id;
    private String username;
    private String email;
    
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
}

/**
 * HOW THE FIX WORKS:
 * - PreparedStatement separates SQL structure from data
 * - User input treated as data, never as SQL code
 * - Database driver handles all escaping automatically
 * - Even malicious input like "admin' OR '1'='1" is treated as literal string
 * 
 * Reference: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
 */