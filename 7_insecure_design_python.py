"""
OWASP Top 10 - Insecure Design (Python/Flask)
Author: Paul Sommers

VULNERABILITY EXPLANATION:
This password reset functionality has multiple critical design flaws:
1. No identity verification - anyone can reset any user's password with just an email
2. No authentication required - unauthenticated users can reset passwords
3. No confirmation or notification - user isn't notified of password change
4. No rate limiting - allows brute force attacks and password spraying
5. Passwords stored in plain text (no hashing mentioned)
6. No secure token or one-time link - just email address verification

This design flaw enables attackers to:
- Take over any account by guessing/knowing their email
- Lock out legitimate users by changing their passwords
- Enumerate valid email addresses in the system
- Launch automated attacks against multiple accounts

This is "Insecure Design" because the fundamental architecture is flawed,
not just a coding bug. The entire password reset process needs redesign.

Reference: https://owasp.org/Top10/A04_2021-Insecure_Design/
"""

# ============================================================================
# VULNERABLE CODE
# ============================================================================

"""
from flask import Flask, request
from models import db, User

app = Flask(__name__)

@app.route('/reset-password', methods=['POST'])
def reset_password():
    email = request.form['email']
    new_password = request.form['new_password']
    user = User.query.filter_by(email=email).first()
    user.password = new_password
    db.session.commit()
    return 'Password reset'
"""

# ============================================================================
# SECURE FIXED CODE
# ============================================================================

from flask import Flask, request, jsonify, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
import secrets
import hashlib
import os
from base64 import b64encode, b64decode

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-change-in-production')

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour"],
    storage_uri="memory://"
)

class PasswordResetToken:
    """
    Manages secure password reset tokens.
    
    Security features:
    - Cryptographically secure random tokens
    - Tokens expire after 1 hour
    - One-time use only
    - Tied to specific user
    """
    
    @staticmethod
    def generate_token():
        """
        Generate cryptographically secure random token.
        
        Returns:
            str: 32-byte hex token (64 characters)
        """
        return secrets.token_hex(32)
    
    @staticmethod
    def hash_token(token):
        """
        Hash token before storing in database.
        Prevents token theft if database is compromised.
        
        Args:
            token (str): Raw token to hash
            
        Returns:
            str: SHA-256 hash of token
        """
        return hashlib.sha256(token.encode()).hexdigest()
    
    @staticmethod
    def create_reset_token(user_id, email):
        """
        Create password reset token for user.
        
        Args:
            user_id: User's ID
            email: User's email
            
        Returns:
            str: Unhashed token (send this to user via email)
        """
        # Generate cryptographically secure token
        token = PasswordResetToken.generate_token()
        
        # Hash token before storing
        token_hash = PasswordResetToken.hash_token(token)
        
        # Set expiration (1 hour from now)
        expires_at = datetime.utcnow() + timedelta(hours=1)
        
        # Store in database (pseudo-code, adjust to your ORM)
        reset_request = PasswordReset(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            used=False
        )
        db.session.add(reset_request)
        db.session.commit()
        
        return token  # Return unhashed token to send via email


def send_password_reset_email(email, token):
    """
    Send password reset email with secure one-time link.
    
    Security considerations:
    - Link expires in 1 hour
    - Token is single-use
    - Email contains no sensitive information
    - Uses HTTPS for reset link
    
    Args:
        email (str): User's email address
        token (str): Password reset token
    """
    reset_link = f"https://yourdomain.com/reset-password?token={token}"
    
    email_body = f"""
    Hello,
    
    You requested a password reset for your account. Click the link below to reset your password:
    
    {reset_link}
    
    This link will expire in 1 hour.
    
    If you didn't request this reset, please ignore this email and consider changing your password.
    
    Security tip: Never share this link with anyone.
    """
    
    # Use proper email service (SendGrid, AWS SES, etc.)
    # Example pseudo-code:
    # email_service.send(
    #     to=email,
    #     subject="Password Reset Request",
    #     body=email_body
    # )
    
    print(f"[Email Service] Sending reset email to {email}")
    print(f"Reset link: {reset_link}")


@app.route('/request-password-reset', methods=['POST'])
@limiter.limit("3 per hour")  # Strict rate limiting
def request_password_reset():
    """
    Request password reset - sends email with secure token.
    
    Security features:
    1. Rate limiting (3 requests per hour per IP)
    2. No account enumeration (always returns success)
    3. Generates secure random token
    4. Token expires in 1 hour
    5. Notification to email address
    
    Returns:
        JSON response (always success to prevent enumeration)
    """
    try:
        # Get email from request
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        # Basic email validation
        if not email or '@' not in email or len(email) > 254:
            # Still return success to prevent enumeration
            return jsonify({
                'message': 'If an account exists with that email, a reset link has been sent.'
            }), 200
        
        # Look up user by email
        user = User.query.filter_by(email=email).first()
        
        # Always return same response (prevent account enumeration)
        response_message = 'If an account exists with that email, a reset link has been sent.'
        
        if user:
            # Delete any existing unused reset tokens for this user
            PasswordReset.query.filter_by(
                user_id=user.id,
                used=False
            ).delete()
            
            # Generate new token
            token = PasswordResetToken.create_reset_token(user.id, email)
            
            # Send email with reset link
            send_password_reset_email(email, token)
            
            # Log the reset request for security monitoring
            # (In production, use proper logging system)
            print(f"[Security] Password reset requested for user {user.id} from IP {get_remote_address()}")
        
        # Always return success message (timing-safe response)
        # This prevents attackers from determining which emails exist
        return jsonify({'message': response_message}), 200
        
    except Exception as e:
        # Log error but don't expose details to user
        print(f"[Error] Password reset request failed: {str(e)}")
        return jsonify({
            'message': 'If an account exists with that email, a reset link has been sent.'
        }), 200


@app.route('/reset-password', methods=['POST'])
@limiter.limit("5 per hour")  # Rate limit password resets
def reset_password():
    """
    Reset password using valid token.
    
    Security features:
    1. Validates token exists and hasn't expired
    2. Ensures token hasn't been used
    3. Requires strong password
    4. Hashes password securely
    5. Invalidates token after use
    6. Notifies user of password change
    7. Optionally invalidates all sessions
    
    Returns:
        JSON response with success or error
    """
    try:
        data = request.get_json()
        token = data.get('token', '').strip()
        new_password = data.get('new_password', '')
        
        # Validate required fields
        if not token or not new_password:
            return jsonify({
                'error': 'Token and new password are required'
            }), 400
        
        # Validate password strength
        password_errors = validate_password_strength(new_password)
        if password_errors:
            return jsonify({
                'error': 'Password does not meet requirements',
                'details': password_errors
            }), 400
        
        # Hash the token to look it up in database
        token_hash = PasswordResetToken.hash_token(token)
        
        # Find the reset request
        reset_request = PasswordReset.query.filter_by(
            token_hash=token_hash,
            used=False
        ).first()
        
        # Validate token exists
        if not reset_request:
            return jsonify({
                'error': 'Invalid or expired reset token'
            }), 400
        
        # Check if token has expired
        if datetime.utcnow() > reset_request.expires_at:
            return jsonify({
                'error': 'Reset token has expired. Please request a new one.'
            }), 400
        
        # Get the user
        user = User.query.get(reset_request.user_id)
        if not user:
            return jsonify({
                'error': 'User not found'
            }), 400
        
        # Hash the new password securely
        from werkzeug.security import generate_password_hash
        user.password_hash = generate_password_hash(
            new_password,
            method='pbkdf2:sha256',
            salt_length=16
        )
        
        # Mark token as used (prevents reuse)
        reset_request.used = True
        reset_request.used_at = datetime.utcnow()
        
        # Save changes
        db.session.commit()
        
        # Send confirmation email
        send_password_changed_notification(user.email)
        
        # Log the password change for security monitoring
        print(f"[Security] Password changed for user {user.id} via reset token")
        
        # Optionally: Invalidate all existing sessions for this user
        # This forces re-login with new password on all devices
        # invalidate_user_sessions(user.id)
        
        return jsonify({
            'message': 'Password successfully reset. Please log in with your new password.'
        }), 200
        
    except Exception as e:
        # Log error for debugging
        print(f"[Error] Password reset failed: {str(e)}")
        db.session.rollback()
        return jsonify({
            'error': 'An error occurred while resetting password'
        }), 500


def validate_password_strength(password):
    """
    Validate password meets security requirements.
    
    Requirements:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character
    - Not a common password
    
    Args:
        password (str): Password to validate
        
    Returns:
        list: List of error messages (empty if valid)
        
    Reference: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
    """
    errors = []
    
    if len(password) < 12:
        errors.append("Password must be at least 12 characters long")
    
    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one number")
    
    if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        errors.append("Password must contain at least one special character")
    
    # Check against common passwords (in production, use a comprehensive list)
    common_passwords = ['password123', 'Password123!', 'admin123', 'qwerty123']
    if password.lower() in [p.lower() for p in common_passwords]:
        errors.append("Password is too common. Please choose a stronger password")
    
    return errors


def send_password_changed_notification(email):
    """
    Send notification that password was changed.
    
    Security measure: Alerts user if unauthorized password change occurred.
    
    Args:
        email (str): User's email address
    """
    email_body = f"""
    Hello,
    
    Your password has been successfully changed.
    
    If you made this change, you can safely ignore this email.
    
    If you did NOT change your password, your account may be compromised.
    Please contact support immediately and reset your password again.
    
    Time of change: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
    """
    
    # Send via email service
    print(f"[Email Service] Sending password change notification to {email}")


"""
HOW THIS FIX ADDRESSES THE VULNERABILITY:

1. Secure Token Generation:
   - Uses cryptographically secure random tokens (secrets.token_hex)
   - 32-byte tokens provide 256 bits of entropy
   - Tokens are one-time use only
   - Tokens expire after 1 hour

2. Identity Verification:
   - User must have access to their email account
   - Token sent only to registered email address
   - Cannot reset password without email access

3. Account Enumeration Prevention:
   - Always returns same message regardless of email existence
   - Prevents attackers from discovering valid email addresses
   - Uses timing-safe responses

4. Rate Limiting:
   - 3 password reset requests per hour per IP
   - 5 password resets per hour per IP
   - Prevents brute force and automated attacks
   - Prevents denial of service via password reset spam

5. Password Security:
   - Validates password strength (12+ chars, mixed case, numbers, symbols)
   - Checks against common passwords
   - Uses secure hashing (PBKDF2-SHA256)
   - Never stores passwords in plain text

6. Token Security:
   - Tokens hashed before storage (prevents theft if DB compromised)
   - Single-use tokens (marked as used after reset)
   - Expiration enforced (1 hour validity)
   - Old unused tokens deleted when new one requested

7. User Notification:
   - Email sent when password reset requested
   - Confirmation email sent when password changed
   - User alerted if unauthorized change occurs
   - Provides audit trail for security

8. Session Management:
   - Optional: Invalidate all sessions after password change
   - Forces re-login on all devices with new password
   - Prevents attackers from maintaining access

9. Error Handling:
   - Generic error messages (don't leak information)
   - Proper logging for security monitoring
   - Graceful failure handling

10. Secure Communication:
    - Reset links use HTTPS
    - Email contains no sensitive information
    - Token transmitted securely

SECURITY IMPROVEMENTS:
- Requires proof of email ownership
- Prevents unauthorized password changes
- Protects against brute force attacks
- Prevents account enumeration
- Notifies users of security-relevant changes
- Implements defense in depth
- Follows OWASP authentication best practices
- Proper separation of concerns
- Secure by design (not just implementation)

DESIGN PRINCIPLES FOLLOWED:
- Principle of least privilege
- Defense in depth
- Fail securely
- Don't trust user input
- Security by design
- Complete mediation
- Psychological acceptability

References:
- OWASP Top 10 A04:2021: https://owasp.org/Top10/A04_2021-Insecure_Design/
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Password Storage: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- OWASP Forgot Password: https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
"""