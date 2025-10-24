from dj_rest_auth.jwt_auth import JWTCookieAuthentication
from rest_framework.authentication import SessionAuthentication, BaseAuthentication
from rest_framework.exceptions import PermissionDenied
from django.conf import settings


class CSRFProtectionMixin:
    """
    Mixin that provides CSRF checking logic using double-submit cookie pattern.
    Can be used by authentication classes to add CSRF protection.
    """
    
    @staticmethod
    def is_browser_request(request):
        """
        Determine if request is from a browser by checking Origin/Referer headers.
        Browsers automatically send these headers; mobile/desktop apps typically don't.
        """
        origin = request.headers.get("Origin")
        referer = request.headers.get("Referer")
        
        if origin and (origin.startswith(settings.FRONTEND_URL) or origin in settings.CSRF_TRUSTED_ORIGINS):
            return True
        
        if referer and (referer.startswith(settings.FRONTEND_URL) or any(referer.startswith(trusted) for trusted in settings.CSRF_TRUSTED_ORIGINS)):
            return True
        
        return False
    
    @staticmethod
    def check_csrf(request):
        """
        Check CSRF token using double-submit cookie pattern.
        Raises PermissionDenied if CSRF check fails.
        """
        csrf_token_header = request.META.get('HTTP_X_CSRFTOKEN', '')
        csrf_token_cookie = request.COOKIES.get('csrftoken', '')
        
        if not csrf_token_header:
            raise PermissionDenied('CSRF token missing from header.')
        
        if not csrf_token_cookie:
            raise PermissionDenied('CSRF token missing from cookie.')
        
        if csrf_token_header != csrf_token_cookie:
            raise PermissionDenied('CSRF token mismatch.')


class CSRFCheckOnly(CSRFProtectionMixin, BaseAuthentication):
    """
    Authentication class that ONLY enforces CSRF for browser requests.
    Does not actually authenticate - returns None to allow other auth or no auth.
    
    Useful for endpoints like token refresh that don't need user authentication
    but should still be protected against CSRF for browser clients.
    """
    
    def authenticate(self, request):
        # Only check CSRF for browser requests on unsafe methods
        if self.is_browser_request(request) and request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            self.check_csrf(request)
        
        # Return None = "I didn't authenticate, but I didn't fail either"
        # This allows the endpoint to proceed without authentication
        return None


class JWTCookieAuthenticationWithCSRF(CSRFProtectionMixin, JWTCookieAuthentication):
    """
    JWT Cookie authentication with CSRF protection for unsafe HTTP methods.
    
    Only enforces CSRF when JWT is in cookies (browser clients).
    Mobile/desktop apps using Authorization header are not affected.
    """
    
    def authenticate(self, request):
        # Try JWT cookie authentication first
        result = JWTCookieAuthentication.authenticate(self, request)
        
        if result is not None:
            # JWT auth succeeded - enforce CSRF for browser requests on unsafe methods
            if self.is_browser_request(request) and request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
                self.check_csrf(request)  # Use mixin's method
            return result
        
        return result