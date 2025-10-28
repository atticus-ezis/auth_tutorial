from rest_framework.views import APIView, csrf_exempt
from dj_rest_auth.views import PasswordResetConfirmView, LoginView, LogoutView
from dj_rest_auth.registration.views import RegisterView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny 
from allauth.account.utils import url_str_to_user_pk 
from rest_framework_simplejwt.tokens import RefreshToken
import traceback
from dj_rest_auth.jwt_auth import set_jwt_cookies
from allauth.account.models import EmailConfirmation, EmailConfirmationHMAC
from rest_framework.exceptions import ValidationError, PermissionDenied
from django.contrib.auth import get_user_model
from django.middleware.csrf import get_token
from users.mixins import CookiesOrAuthorizationJWTMixin
from users.authentication import CSRFCheckOnly
from dj_rest_auth.jwt_auth import get_refresh_view, JWTCookieAuthentication, JWTAuthentication
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.utils.decorators import method_decorator

class CustomVerifyEmailView(CookiesOrAuthorizationJWTMixin, APIView):
    """
    Email verification view that adapts response format based on Origin header.
    CSRF exempt for better UX since the verification key already provides security.
    """
    permission_classes = [AllowAny]
    authentication_classes = []
    
    # @method_decorator(csrf_exempt)
    # def dispatch(self, *args, **kwargs):
    #     return super().dispatch(*args, **kwargs)  
    
    def post(self, request):
        key = request.data.get("key")
        if not key:
            raise ValidationError({"key": [("Missing verification key.")]})

        try:
            emailconfirmation = EmailConfirmation.objects.filter(
                key=key
            ).first() or EmailConfirmationHMAC.from_key(key)
            if not emailconfirmation:
                raise ValidationError({"key": [("Invalid verification key.")]})

            # Confirm the email address (marks it as verified in the database)
            emailconfirmation.confirm(request)
            
            user = emailconfirmation.email_address.user

            refresh = RefreshToken.for_user(user)
            access = refresh.access_token

            return Response(
                {
                    "detail": "Email confirmed successfully",
                    "access": str(access),
                    "refresh": str(refresh),
                },
                status=status.HTTP_200_OK,
            )
            

        except Exception as e:
            print(f"Error: {e}")
            print(traceback.format_exc())
            return Response(
                {"key": [f"Error: {str(e)}"]},
                status=status.HTTP_400_BAD_REQUEST,
            )


class CustomPasswordResetConfirmView(CookiesOrAuthorizationJWTMixin, PasswordResetConfirmView):
    """
    Custom password reset confirm view that automatically logs the user in
    after successful password reset by returning JWT tokens.
    Response format adapts based on Origin header.
    CSRF exempt for better UX since the token in the URL already provides security.
    """
    permission_classes = [AllowAny]  
    authentication_classes = []
    
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs) 
    
    def post(self, request, *args, **kwargs):
        try:
            response = super().post(request, *args, **kwargs)   

            if response.status_code == status.HTTP_200_OK:
                User = get_user_model()
                uid = request.data.get("uid")
                
                # Decode uid using allauth's base36 decoder
                user_pk = url_str_to_user_pk(uid)
                user = User.objects.get(pk=user_pk)
                
                # Generate JWT tokens
                refresh = RefreshToken.for_user(user)
                access = refresh.access_token
                
                # Add tokens to response data (mixin will handle cookie/JSON formatting)
                response.data["access"] = str(access)
                response.data["refresh"] = str(refresh)
            
            return response
            
        except Exception as e:
            print(f"Error in CustomPasswordResetConfirmView: {e}")
            print(traceback.format_exc())
            return Response(
                {"detail": [f"Error: {str(e)}"]},
                status=status.HTTP_400_BAD_REQUEST,
            )


# Custom views with CookiesOrAuthorizationJWTMixin for login, registration, and token refresh
class CustomLoginView(CookiesOrAuthorizationJWTMixin, LoginView):
    """Login view that adapts response format based on Origin header."""
    pass


class CustomRegisterView(CookiesOrAuthorizationJWTMixin, RegisterView):
    """Registration view that adapts response format based on Origin header."""
    pass


 # dj reest auth logout doesn't support api JWT
class CustomLogoutView(APIView):
    """
    Custom logout view that handles both cookie-based (browser) and header-based (app) JWT authentication.
    CSRF exempt for better UX - logout is typically a safe operation.
    """
    authentication_classes = [JWTAuthentication, JWTCookieAuthentication] # not necessary? 
    permission_classes = [AllowAny]
    
    
    def post(self, request, *args, **kwargs):
        """
        Handle logout for both cookie and header-based refresh tokens.
        """
        # Check if refresh token is in request data (for app authentication)
        refresh_token = request.data.get('refresh')
        
        # If no refresh token in data, try to get it from cookies (for browser authentication)
        if not refresh_token:
            refresh_token = request.COOKIES.get('jwt-refresh-token')
        
        # If still no refresh token, return error
        if not refresh_token:
            return Response(
                {'detail': 'Refresh token was not included in request data or cookie data.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Blacklist the refresh token
            token = RefreshToken(refresh_token)
            token.blacklist()
            
            # Create response
            response = Response(
                {'detail': 'Successfully logged out.'},
                status=status.HTTP_200_OK
            )
            
            # If the token was in cookies, delete the cookie
            if request.COOKIES.get('jwt-refresh-token'):
                response.delete_cookie('jwt-refresh-token')
                
            if request.COOKIES.get('jwt-auth'):
                response.delete_cookie('jwt-auth')
            
            return response
            
        except Exception as e:
            return Response(
                {'detail': f'Error during logout: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )

    

# Get dj-rest-auth's refresh view class
dj_rest_auth_refresh_view_class = get_refresh_view()

class CustomTokenRefreshView(CookiesOrAuthorizationJWTMixin, dj_rest_auth_refresh_view_class):
    """
    Token refresh view that supports both cookie and body-based refresh tokens.
    Uses dj-rest-auth's built-in cookie support with CSRF protection.
    
    CSRF protection is enforced via CSRFCheckOnly authentication class for browser requests.
    This class checks CSRF without requiring user authentication (since refresh tokens
    are validated directly by the endpoint logic).
    """
    authentication_classes = [CSRFCheckOnly, JWTCookieAuthentication]  
    pass
    
