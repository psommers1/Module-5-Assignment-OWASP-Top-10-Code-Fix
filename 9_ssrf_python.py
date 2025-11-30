"""
OWASP Top 10 - Server-Side Request Forgery (SSRF) (Python)
Author: Paul Sommers

VULNERABILITY: Accepts user URL and makes server-side request without validation
RISK: Access internal networks, steal cloud credentials, bypass firewalls, port scanning
Reference: https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
"""

# ============================================================================
# VULNERABLE CODE
# ============================================================================
"""
import requests

url = input("Enter URL: ")
response = requests.get(url)
print(response.text)
"""

# ============================================================================
# SECURE FIXED CODE
# ============================================================================

import requests
from urllib.parse import urlparse
import ipaddress
import socket

class SSRFProtection:
    """SSRF protection with URL validation"""
    
    PRIVATE_IP_RANGES = [
        ipaddress.ip_network('127.0.0.0/8'),      # Loopback
        ipaddress.ip_network('10.0.0.0/8'),       # Private
        ipaddress.ip_network('172.16.0.0/12'),    # Private
        ipaddress.ip_network('192.168.0.0/16'),   # Private
        ipaddress.ip_network('169.254.0.0/16'),   # AWS metadata!
    ]
    
    @staticmethod
    def is_private_ip(ip_str):
        """Check if IP is private"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in network for network in SSRFProtection.PRIVATE_IP_RANGES)
        except:
            return True
    
    @staticmethod
    def validate_url(url):
        """Validate URL to prevent SSRF"""
        try:
            parsed = urlparse(url)
            
            # Only allow http/https
            if parsed.scheme not in ['http', 'https']:
                return False, "Only http/https allowed"
            
            # Block localhost
            if parsed.hostname in ['localhost', '127.0.0.1', '::1']:
                return False, "Localhost not allowed"
            
            # Resolve and check all IPs
            addr_info = socket.getaddrinfo(parsed.hostname, None)
            for info in addr_info:
                ip_str = info[4][0]
                if SSRFProtection.is_private_ip(ip_str):
                    return False, f"Private IP not allowed: {ip_str}"
            
            # Only allow ports 80, 443
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            if port not in [80, 443]:
                return False, "Only ports 80, 443 allowed"
            
            return True, "Valid"
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def fetch_url_safely(url, timeout=5):
        """Safely fetch URL with validation"""
        is_valid, error = SSRFProtection.validate_url(url)
        if not is_valid:
            return {'success': False, 'error': error}
        
        try:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=False  # Prevents DNS rebinding
            )
            return {
                'success': True,
                'content': response.text,
                'status': response.status_code
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

# Example usage
if __name__ == "__main__":
    # Safe request
    result = SSRFProtection.fetch_url_safely("https://api.github.com/zen")
    print(result)
    
    # Blocked request
    result = SSRFProtection.fetch_url_safely("http://169.254.169.254/metadata")
    print(result)  # Error: Private IP not allowed

"""
HOW THE FIX WORKS:
- Validates URL scheme (only http/https)
- Blocks private IP ranges and localhost
- Resolves DNS and validates all IPs
- Restricts to ports 80 and 443
- Disables redirects to prevent DNS rebinding

Reference: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
"""