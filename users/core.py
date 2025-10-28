from rest_framework.exceptions import PermissionDenied
from django.conf import settings

# Usefule helper functions

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