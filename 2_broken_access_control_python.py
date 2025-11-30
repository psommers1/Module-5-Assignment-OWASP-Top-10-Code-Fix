"""
OWASP Top 10 - Broken Access Control (Python)
Author: Paul Sommers

VULNERABILITY: Exposes user account data to anyone who knows a user_id
RISK: Data breaches, privacy violations, unauthorized access
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

app = Flask(__name__)

def login_required(f):
    """Ensure user is authenticated"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            abort(401, description="Authentication required")
        return f(*args, **kwargs)
    return decorated_function

def check_ownership(f):
    """Ensure user owns the resource"""
    @wraps(f)
    def decorated_function(user_id, *args, **kwargs):
        if str(session.get('user_id')) != str(user_id):
            if not session.get('is_admin', False):
                abort(403, description="Forbidden")
        return f(user_id, *args, **kwargs)
    return decorated_function

@app.route('/account/<user_id>')
@login_required
@check_ownership
def get_account(user_id):
    """Get account with access control"""
    user = db.query(User).filter_by(id=user_id).first()
    
    if not user:
        abort(404, description="User not found")
    
    # Return only non-sensitive data
    sanitized_data = {
        'id': user.id,
        'username': user.username,
        'email': user.email
    }
    return jsonify(sanitized_data)

"""
HOW THE FIX WORKS:
1. @login_required ensures user is authenticated
2. @check_ownership ensures user can only access their own account
3. Data sanitization excludes passwords and sensitive fields

SECURITY IMPROVEMENTS:
- Prevents unauthorized access
- Prevents horizontal privilege escalation
- Reduces data exposure
"""