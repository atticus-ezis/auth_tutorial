from dj_rest_auth.jwt_auth import JWTCookieAuthentication
from rest_framework.authentication import BaseAuthentication
from users.core import is_browser_request, check_csrf




class CSRFCheckOnly(BaseAuthentication):
    """
    Authentication class that ONLY enforces CSRF for browser requests.
    Does not actually authenticate - returns None to allow other auth or no auth.
    
    Useful for endpoints like token refresh that don't need user authentication
    but should still be protected against CSRF for browser clients.
    """
    
    def authenticate(self, request):
        # Only check CSRF for browser requests on unsafe methods
        if is_browser_request(request) and request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            check_csrf(request)
    
        return None


class JWTCookieAuthenticationWithCSRF(JWTCookieAuthentication):
    """
    JWT Cookie authentication with CSRF protection for unsafe HTTP methods.
    
    Only enforces CSRF when JWT is in cookies (browser clients).
    Mobile/desktop apps using Authorization header are not affected.
    """
    
    def authenticate(self, request):
        result = JWTCookieAuthentication.authenticate(self, request)
        
        if result is not None:
            check_csrf(request)
        return result