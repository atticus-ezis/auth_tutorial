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
from dj_rest_auth.jwt_auth import get_refresh_view
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.utils.decorators import method_decorator

class CustomVerifyEmailView(CookiesOrAuthorizationJWTMixin, APIView):
    """
    Email verification view that adapts response format based on Origin header.
    CSRF exempt for better UX since the verification key already provides security.
    """
    permission_classes = [AllowAny]
    authentication_classes = []
    
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)  
    
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
        print("######################### CUSTOM PASSWORD RESET CONFIRM ACTIVE")
        print(f"######################### REQUEST DATA: {request.data}")
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


 
class CustomLogoutView(LogoutView):
    """
    Logout view for JWT-authenticated users.
    
    CSRF protection is automatically enforced by JWTCookieAuthenticationWithCSRF
    for cookie-based requests.
    """
    pass
    

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
    authentication_classes = [CSRFCheckOnly]  
    
