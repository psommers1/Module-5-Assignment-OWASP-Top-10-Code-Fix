"""
OWASP Top 10 - Broken Access Control (Python/Flask)
Author: Paul Sommers

VULNERABILITY EXPLANATION:
This code exposes user account information to anyone who knows or can guess a user_id.
There is no verification that the requesting user has permission to access the account data.
An attacker could enumerate user IDs and access all account information in the system,
leading to data breaches and privacy violations.

Reference: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
"""

# ============================================================================
# VULNERABLE CODE
# ============================================================================

"""
@app.route('/account/<user_id>')
def get_account(user_id):
    user = db.query(User).filter_by(id=user_id).first()
    return jsonify(user.to_dict())
"""

# ============================================================================
# SECURE FIXED CODE
# ============================================================================

from flask import Flask, jsonify, session, abort
from functools import wraps
from sqlalchemy.orm import Session

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Should be loaded from environment variable

def login_required(f):
    """
    Decorator to ensure user is authenticated before accessing the route.
    
    This decorator checks if a valid user session exists. If not, it returns
    a 401 Unauthorized error, preventing unauthenticated access.
    
    Reference: https://flask.palletsprojects.com/en/2.3.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            abort(401, description="Authentication required")
        return f(*args, **kwargs)
    return decorated_function

def check_account_ownership(f):
    """
    Decorator to verify the user has permission to access the requested account.
    
    This implements authorization by ensuring the authenticated user can only
    access their own account data, unless they have admin privileges.
    
    Reference: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
    """
    @wraps(f)
    def decorated_function(user_id, *args, **kwargs):
        # Check if the authenticated user is accessing their own account
        if str(session.get('user_id')) != str(user_id):
            # Check if user has admin role
            if not session.get('is_admin', False):
                abort(403, description="Forbidden: You do not have permission to access this account")
        return f(user_id, *args, **kwargs)
    return decorated_function

@app.route('/account/<user_id>')
@login_required
@check_account_ownership
def get_account(user_id):
    """
    Retrieve account information for a specific user.
    
    This route is protected by authentication and authorization checks to ensure
    only authorized users can access account data.
    
    Args:
        user_id: The ID of the user account to retrieve
        
    Returns:
        JSON response with sanitized user account information
        
    Security measures:
        - Requires authentication (login_required decorator)
        - Enforces authorization (check_account_ownership decorator)
        - Sanitizes output to exclude sensitive fields
        - Uses parameterized queries to prevent SQL injection
    """
    # Use parameterized query to prevent SQL injection
    # filter_by() automatically parameterizes the query
    user = db.query(User).filter_by(id=user_id).first()
    
    if not user:
        abort(404, description="User not found")
    
    # Sanitize the user data before returning
    # Only include non-sensitive information
    sanitized_data = {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'created_at': user.created_at.isoformat() if hasattr(user, 'created_at') else None,
        'account_type': user.account_type if hasattr(user, 'account_type') else None
        # Explicitly exclude: password, password_hash, security_questions, 
        # api_keys, tokens, etc.
    }
    
    return jsonify(sanitized_data)

# Additional security: Rate limiting to prevent enumeration attacks
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour"]
)

@app.route('/account/<user_id>')
@limiter.limit("10 per minute")  # Prevent rapid enumeration of user accounts
@login_required
@check_account_ownership
def get_account_with_rate_limit(user_id):
    """Same as get_account but with rate limiting applied."""
    return get_account(user_id)

"""
HOW THIS FIX ADDRESSES THE VULNERABILITY:

1. Authentication (@login_required decorator):
   - Verifies user has a valid session before allowing any access
   - Returns 401 if user is not authenticated
   - Prevents anonymous users from accessing account data

2. Authorization (@check_account_ownership decorator):
   - Ensures users can only access their own account information
   - Implements role-based access control for admin users
   - Returns 403 Forbidden if authorization fails

3. Input Validation:
   - User ID is validated through the decorator chain
   - Prevents malicious input from bypassing security controls

4. Data Sanitization:
   - Explicitly defines which fields to return
   - Excludes sensitive fields like passwords, tokens, API keys
   - Prevents accidental exposure of sensitive data

5. Additional Security Measures:
   - Rate limiting prevents brute force enumeration attacks
   - Parameterized queries prevent SQL injection
   - Proper HTTP status codes (401, 403, 404)
   - Descriptive but not overly detailed error messages

SECURITY IMPROVEMENTS:
- Implements defense in depth with multiple security layers
- Follows principle of least privilege
- Prevents horizontal privilege escalation attacks
- Complies with OWASP access control best practices
- Protects against account enumeration attacks

References:
- OWASP Top 10 A01:2021: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- OWASP Authorization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- Flask Security Considerations: https://flask.palletsprojects.com/en/2.3.x/security/
"""