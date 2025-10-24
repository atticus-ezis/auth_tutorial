from dj_rest_auth.jwt_auth import set_jwt_cookies
from django.middleware.csrf import get_token
from django.conf import settings


class CookiesOrAuthorizationJWTMixin:
    """
    Mixin that adapts JWT token delivery based on client type.
    
    Default behavior (browsers): HttpOnly cookies with CSRF protection
    Mobile/Desktop apps: JSON tokens in response body
    
    When JWT_AUTH_HTTPONLY=True (recommended), dj-rest-auth automatically sets
    HttpOnly cookies by default. This mixin only intervenes for non-browser clients.
    """

    def is_browser_request(self, request):
        """
        Determine if request is from a browser by checking Origin/Referer headers.
        
        Browsers automatically send Origin header on CORS requests.
        Mobile/desktop apps typically don't send these headers.
        """
        origin = request.headers.get("Origin")
        referer = request.headers.get("Referer")
    
        if origin and (origin.startswith(settings.FRONTEND_URL) or origin in settings.CSRF_TRUSTED_ORIGINS):
            return True
        
        if referer and (referer.startswith(settings.FRONTEND_URL) or referer in settings.CSRF_TRUSTED_ORIGINS):
            return True
        
        return False
    
    def finalize_response(self, request, response, *args, **kwargs):
        """
        Override finalize_response to handle mobile/desktop clients.
        
        - Browsers: Let dj-rest-auth handle it (cookies set via JWT_AUTH_HTTPONLY)
        - Mobile/Desktop: Extract tokens from cookies → move to JSON body
        """
        response = super().finalize_response(request, response, *args, **kwargs)

        if response.status_code not in [200, 201]:
            return response
        
        if not hasattr(response, "data") or not isinstance(response.data, dict):
            return response

        is_browser = self.is_browser_request(request)

        access = response.data.get("access") 
        refresh = response.data.get("refresh") 

        if not access or not refresh:
            access_cookie = response.cookies.get(settings.REST_AUTH.get('JWT_AUTH_COOKIE', 'jwt-auth'))
            refresh_cookie = response.cookies.get(settings.REST_AUTH.get('JWT_AUTH_REFRESH_COOKIE', 'jwt-refresh-token'))
            access = access_cookie.value if access_cookie else access
            refresh = refresh_cookie.value if refresh_cookie else refresh

        if not access or not refresh:
            print(f"#### No tokens detected! refresh {refresh}, access: {access}")
            return response

        if is_browser:

            set_jwt_cookies(response, access, refresh)
            
            # Get CSRF token - this ensures it's created and will be set in cookie by middleware
            # get_token() returns a masked token, but we need the secret token that matches the cookie
            get_token(request)  # Ensure token is created
            
            # Get the actual secret token from request (this is what goes in the cookie)
            csrf_token = request.META.get("CSRF_COOKIE")
            
            response.data.pop("access", None)
            response.data.pop("refresh", None)
            if csrf_token:
                response.data['csrf_token'] = csrf_token
            response.data['authType'] = 'cookie'

        else:

            response.data['access'] = access
            response.data['refresh'] = refresh
            response.data['authType'] = 'bearer'
            response.cookies.clear()
            
        return response