from rest_framework.exceptions import PermissionDenied
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import ValidationError

# Usefule helper functions

def make_tokens(user, aud):
    refresh = RefreshToken.for_user(user)
    refresh["aud"] = aud
    access = refresh.access_token
    access["aud"] = aud
    return access, refresh


def check_csrf(request):
    """
    Check CSRF token using double-submit cookie pattern.
    Raises PermissionDenied if CSRF check fails.
    """
    # Django converts HTTP headers to HTTP_ prefix in META
    # e.g., 'X-CSRFToken' header becomes 'HTTP_X_CSRFTOKEN' in request.META
    csrf_token_header = request.META.get('HTTP_X_CSRFTOKEN', '')
    csrf_token_cookie = request.COOKIES.get('csrftoken_cookie', '')
    
    if not csrf_token_header:
        raise PermissionDenied('CSRF token missing from header.')
    
    if not csrf_token_cookie:
        raise PermissionDenied('CSRF token missing from cookie.')
    
    if csrf_token_header != csrf_token_cookie:
        raise PermissionDenied('CSRF token mismatch.')


def client_wants_app_tokens(request):
        return request.headers.get("X-Client", "").lower() == "app"

def require_auth_type(request):
    auth_type = request.headers.get('X-Client')
    if not auth_type:
        raise ValidationError({"detail": [("Missing X-Client header.")]})
    if auth_type not in ['browser', 'app']:
        raise ValidationError({"detail": [("Invalid authentication type. expected 'browser' or 'app', got '{auth_type}'.")]})
    return auth_type
