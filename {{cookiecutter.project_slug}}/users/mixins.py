from dj_rest_auth.jwt_auth import set_jwt_cookies
from django.middleware.csrf import get_token
from django.conf import settings
from rest_framework.response import Response
from django.middleware import csrf
from users.core import make_tokens, client_wants_app_tokens

jwt_auth_cookie = settings.REST_AUTH.get('JWT_AUTH_COOKIE', 'jwt-auth')
jwt_refresh_cookie = settings.REST_AUTH.get('JWT_AUTH_REFRESH_COOKIE', 'jwt-refresh-token')
csrf_cookie_name = settings.CSRF_COOKIE_NAME

class HybridAuthMixin:
    """
    Mixin that adapts JWT token delivery based on client type (X-Client header).
    
    - X-Client: app → Returns tokens in JSON body
    - No X-Client header → Returns tokens in HttpOnly cookies (browser)
    
    Works with dj-rest-auth views that already create tokens in their response.
    The mixin extracts existing tokens and formats them appropriately.
    """
    def issue_for_browser(self, request, response, access, refresh):
        """Set tokens as HttpOnly cookies for browser clients."""
        # Remove tokens from response body if present
        if hasattr(response, 'data') and isinstance(response.data, dict):
            response.data.pop("access", None)
            response.data.pop("refresh", None)
        
        # Set JWT tokens as HttpOnly cookies
        response.set_cookie(
            jwt_auth_cookie, 
            str(access),
            httponly=True,
        )
        response.set_cookie(
            jwt_refresh_cookie, 
            str(refresh), 
            httponly=True,
        )

        # --- CSRF: ensure the cookie and exposed token stay in sync ---
        csrf.get_token(request)
        csrf_token = request.META.get("CSRF_COOKIE")
        
        if hasattr(response, 'data') and isinstance(response.data, dict):
            response.data['authType'] = 'cookie'
            response.data['csrfToken'] = csrf_token or ""
        
        return response


    def issue_for_app(self, response, access, refresh):
        """Return tokens in JSON body for mobile/desktop app clients."""
        expires_in = int(access.lifetime.total_seconds()) if hasattr(access, 'lifetime') else None
        if hasattr(response, 'data') and isinstance(response.data, dict):
            response.data["access"] = str(access)
            response.data["refresh"] = str(refresh)
            response.data["token_type"] = "Bearer"
            response.data["expires_in"] = expires_in
            response.data["authType"] = "bearer"

        if jwt_auth_cookie in response.cookies:
            response.delete_cookie(jwt_auth_cookie)
            del response.cookies[jwt_auth_cookie]
        if jwt_refresh_cookie in response.cookies:
            response.delete_cookie(jwt_refresh_cookie)
            del response.cookies[jwt_refresh_cookie]
        if csrf_cookie_name in response.cookies:
            response.delete_cookie(csrf_cookie_name)
            del response.cookies[csrf_cookie_name]
        if 'csrftoken' in response.cookies:
            del response.cookies['csrftoken']
        if 'csrftoken_cookie' in response.cookies:
            del response.cookies['csrftoken_cookie']


        return response

    def _validate_token_has_aud(self, token_str, expected_aud):
        """
        Validate that a token string has the correct audience claim.
        Returns True if valid, False otherwise.
        """
        if not token_str:
            return False
        
        try:
            from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
            from rest_framework_simplejwt.exceptions import TokenError
            
            # Try to decode as access token first
            try:
                token = AccessToken(token_str)
            except TokenError:
                # Try as refresh token
                token = RefreshToken(token_str)
            
            # Check if 'aud' claim exists and matches
            if 'aud' not in token:
                return False
            return token.get('aud') == expected_aud
        except Exception:
            return False
    
    def _get_user_from_response(self, response):
        """Extract user from response data or self."""
        user = getattr(self, "user", None)
        
        if not user and hasattr(response, 'data') and isinstance(response.data, dict):
            # Try to get user from response data (common in registration)
            user_data = response.data.get('user', {})
            if isinstance(user_data, dict):
                user_id = user_data.get('id') or user_data.get('pk')
                if user_id:
                    from django.contrib.auth import get_user_model
                    User = get_user_model()
                    try:
                        user = User.objects.get(pk=user_id)
                    except User.DoesNotExist:
                        pass
        
        return user

    def _get_or_issue_tokens_from_response(self, response, expected_aud):
        access = None
        refresh = None
        
        if hasattr(response, 'data') and isinstance(response.data, dict):
            access = response.data.get("access")
            refresh = response.data.get("refresh")
        
        # If no tokens in body, check cookies (dj-rest-auth might have set them)
        if not access or not refresh:
            jwt_auth_cookie = settings.REST_AUTH.get('JWT_AUTH_COOKIE', 'jwt-auth')
            jwt_refresh_cookie = settings.REST_AUTH.get('JWT_AUTH_REFRESH_COOKIE', 'jwt-refresh-token')
            
            access_cookie = response.cookies.get(jwt_auth_cookie)
            refresh_cookie = response.cookies.get(jwt_refresh_cookie)
            
            if access_cookie:
                access = access_cookie.value
            if refresh_cookie:
                refresh = refresh_cookie.value

        tokens_need_recreation = False
        
        if access and refresh:
            # Validate both tokens have correct audience
            access_valid = self._validate_token_has_aud(access, expected_aud)
            refresh_valid = self._validate_token_has_aud(refresh, expected_aud)
            
            if not access_valid or not refresh_valid:
                tokens_need_recreation = True
        
        # If tokens are missing or invalid, get user and create new tokens with 'aud'
        if not access or not refresh or tokens_need_recreation:
            user = self._get_user_from_response(response)
            
            if user:
                # Create tokens with appropriate audience (always includes 'aud' claim)
                access, refresh = make_tokens(user, expected_aud)
            else:
                # No tokens and no user - return as-is
                if not access and not refresh:
                    return response

            
        return access, refresh

    def finalize_response(self, request, response, *args, **kwargs):
        """
        Adapt response based on client type.
        
        Ensures all tokens have the correct 'aud' (audience) claim:
        - "app" for mobile/desktop clients (X-Client: app header)
        - "browser" for web browsers
        
        For registration/login flows, dj-rest-auth may create tokens.
        This method validates and recreates tokens if they lack the correct 'aud' claim.
        """
        response = super().finalize_response(request, response, *args, **kwargs)
        
        if response.status_code not in [200, 201]:
            return response
        
        expected_aud = "app" if client_wants_app_tokens(request) else "browser"

        access, refresh = self._get_or_issue_tokens_from_response(response, expected_aud)
        
        if client_wants_app_tokens(request):
            return self.issue_for_app(response, access, refresh)
        else:
            return self.issue_for_browser(request, response, access, refresh)

