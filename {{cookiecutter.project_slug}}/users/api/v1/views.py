import logging
from rest_framework.views import APIView
from dj_rest_auth.views import PasswordResetConfirmView, LoginView, PasswordChangeView
from dj_rest_auth.registration.views import RegisterView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from allauth.account.utils import url_str_to_user_pk
from rest_framework_simplejwt.tokens import RefreshToken
from allauth.account.models import EmailConfirmation, EmailConfirmationHMAC
from rest_framework.exceptions import ValidationError
from django.contrib.auth import get_user_model

# from users.mixins import CookiesOrAuthorizationJWTMixin
from dj_rest_auth.jwt_auth import get_refresh_view
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from users.mixins import HybridAuthMixin
from users.core import make_tokens, require_auth_type
from users.authentication import (
    CustomRefreshTokenAuthentication,
    BearerJWTAuthentication,
    CookieJWTAuthenticationWithCSRF,
)
from django.conf import settings


logger = logging.getLogger(__name__)


class CustomVerifyEmailView(HybridAuthMixin, APIView):
    """
    Recieves email verify key and X-Client type from frontend
    mixin returns correct tokens based on X-Client type

    """

    permission_classes = [AllowAny]
    authentication_classes = []

    # @method_decorator(csrf_exempt)
    # def dispatch(self, *args, **kwargs):
    #     return super().dispatch(*args, **kwargs)

    def post(self, request):
        key = request.data.get("key")
        if not key:
            raise ValidationError({"key": ["Missing verification key."]})

        auth_type = require_auth_type(request)  # must know what to return

        try:
            emailconfirmation = EmailConfirmation.objects.filter(
                key=key
            ).first() or EmailConfirmationHMAC.from_key(key)
            if not emailconfirmation:
                raise ValidationError({"key": ["Invalid verification key."]})

            # Confirm the email address (marks it as verified in the database)
            emailconfirmation.confirm(request)

            # Create tokens with correct audience
            user = emailconfirmation.email_address.user
            aud = "app" if auth_type == "app" else "browser"
            access, refresh = make_tokens(user, aud)

            return Response(
                {
                    "detail": "Email confirmed successfully",
                    "access": str(access),
                    "refresh": str(refresh),
                },
                status=status.HTTP_200_OK,
            )

        except Exception as exc:
            logger.exception("Failed to confirm email for key %s", key)
            return Response(
                {"key": [f"Error: {str(exc)}"]},
                status=status.HTTP_400_BAD_REQUEST,
            )


class CustomPasswordResetConfirmView(HybridAuthMixin, PasswordResetConfirmView):
    """
    takes X-Client type and new password from frontend with uid token
    returns correct tokens based on X-Client type
    """

    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_scope = "password_reset"

    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        auth_type = require_auth_type(request)  # must know what to return
        try:
            response = super().post(request, *args, **kwargs)
            if response.status_code == status.HTTP_200_OK:
                User = get_user_model()
                uid = request.data.get("uid")

                # Decode uid using allauth's base36 decoder
                user_pk = url_str_to_user_pk(uid)
                user = User.objects.get(pk=user_pk)

                aud = "app" if auth_type == "app" else "browser"
                access, refresh = make_tokens(user, aud)
                # Add tokens to response data (mixin will handle cookie/JSON formatting)
                response.data["access"] = str(access)
                response.data["refresh"] = str(refresh)
                response.data["message"] = "Password reset successfully"

            return response

        except Exception as exc:
            logger.exception(
                "Password reset confirm failed for uid=%s", request.data.get("uid")
            )
            return Response(
                {"detail": [f"Error: {str(exc)}"]},
                status=status.HTTP_400_BAD_REQUEST,
            )


class CustomLoginView(HybridAuthMixin, LoginView):
    """Login view that adapts response format based on Origin header."""

    authentication_classes = []
    throttle_scope = "login"
    pass


class CustomRegisterView(HybridAuthMixin, RegisterView):
    """Registration view that adapts response format based on Origin header."""

    throttle_scope = "register"
    pass


class CustomPasswordChangeView(HybridAuthMixin, PasswordChangeView):
    """Password change view that adapts response format based on Origin header."""

    throttle_scope = "password_change"
    pass


class CustomLogoutView(APIView):
    """
    Custom logout view that handles both cookie-based (browser) and header-based (app) JWT authentication.
    CSRF exempt for better UX - logout is typically a safe operation.
    """

    authentication_classes = [CookieJWTAuthenticationWithCSRF, BearerJWTAuthentication]
    permission_classes = [IsAuthenticated]
    throttle_scope = "logout"

    def post(self, request, *args, **kwargs):
        """
        Handle logout for both cookie and header-based refresh tokens.
        """
        # Check if refresh token is in request data (for app authentication)
        refresh_token = request.data.get("refresh")

        # If no refresh token in data, try to get it from cookies (for browser authentication)
        if not refresh_token:
            refresh_token = request.COOKIES.get(
                settings.REST_AUTH.get("JWT_AUTH_REFRESH_COOKIE", "jwt-refresh-token")
            )

        # If still no refresh token, return error
        if not refresh_token:
            return Response(
                {
                    "detail": "Refresh token was not included in request data or cookie data."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            # Blacklist the refresh token
            token = RefreshToken(refresh_token)
            token.blacklist()

            # Create response
            response = Response(
                {"detail": "Successfully logged out."}, status=status.HTTP_200_OK
            )

            # If the token was in cookies, delete the cookie
            if request.COOKIES.get(
                settings.REST_AUTH.get("JWT_AUTH_REFRESH_COOKIE", "jwt-refresh-token")
            ):
                response.delete_cookie(
                    settings.REST_AUTH.get(
                        "JWT_AUTH_REFRESH_COOKIE", "jwt-refresh-token"
                    )
                )

            if request.COOKIES.get(
                settings.REST_AUTH.get("JWT_AUTH_COOKIE", "jwt-auth")
            ):
                response.delete_cookie(
                    settings.REST_AUTH.get("JWT_AUTH_COOKIE", "jwt-auth")
                )

            return response

        except Exception as exc:
            logger.exception("Logout failed for user %s", request.user)
            return Response(
                {"detail": f"Error during logout: {str(exc)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )


# Get dj-rest-auth's refresh view class
dj_rest_auth_refresh_view_class = get_refresh_view()


class CustomTokenRefreshView(HybridAuthMixin, dj_rest_auth_refresh_view_class):
    authentication_classes = [CustomRefreshTokenAuthentication]
    throttle_scope = "token_refresh"
