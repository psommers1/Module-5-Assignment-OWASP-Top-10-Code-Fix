"""
OWASP Top 10 - Insecure Design (Python)
Author: Paul Sommers

VULNERABILITY: Password reset with no identity verification or security controls
RISK: Account takeover, unauthorized password changes, no user notification
Reference: https://owasp.org/Top10/A04_2021-Insecure_Design/
"""

# ============================================================================
# VULNERABLE CODE
# ============================================================================
"""
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

from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import secrets
import hashlib
from datetime import datetime, timedelta

app = Flask(__name__)
limiter = Limiter(app=app, key_func=get_remote_address)

def generate_reset_token():
    """Generate cryptographically secure token"""
    return secrets.token_hex(32)

def hash_token(token):
    """Hash token before storing"""
    return hashlib.sha256(token.encode()).hexdigest()

@app.route('/request-password-reset', methods=['POST'])
@limiter.limit("3 per hour")
def request_password_reset():
    """Request password reset - sends email with token"""
    email = request.get_json().get('email')
    user = User.query.filter_by(email=email).first()
    
    # Always return success to prevent email enumeration
    if user:
        token = generate_reset_token()
        token_hash = hash_token(token)
        
        # Store token with expiration (1 hour)
        reset = PasswordReset(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )
        db.session.add(reset)
        db.session.commit()
        
        # Send email with reset link
        send_email(user.email, f"Reset link: /reset?token={token}")
    
    return jsonify({'message': 'If account exists, reset link sent'})

@app.route('/reset-password', methods=['POST'])
@limiter.limit("5 per hour")
def reset_password():
    """Complete password reset with valid token"""
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')
    
    # Validate token
    token_hash = hash_token(token)
    reset = PasswordReset.query.filter_by(token_hash=token_hash, used=False).first()
    
    if not reset or datetime.utcnow() > reset.expires_at:
        return jsonify({'error': 'Invalid or expired token'}), 400
    
    # Update password securely
    user = User.query.get(reset.user_id)
    user.password_hash = hash_password_secure(new_password)
    reset.used = True
    db.session.commit()
    
    return jsonify({'message': 'Password reset successful'})

"""
HOW THE FIX WORKS:
- Secure token sent via email (proves email ownership)
- Rate limiting prevents brute force (3 requests/hour)
- Token expires in 1 hour
- Token is one-time use only
- Always returns same message (prevents email enumeration)
- Password hashed securely

Reference: https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
"""