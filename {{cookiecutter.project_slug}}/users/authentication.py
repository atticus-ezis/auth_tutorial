import logging

from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken

from users.core import check_csrf, client_type

logger = logging.getLogger(__name__)

jwt_refresh_cookie = settings.REST_AUTH.get(
    "JWT_AUTH_REFRESH_COOKIE", "jwt-refresh-token"
)
jwt_auth_cookie = settings.REST_AUTH.get("JWT_AUTH_COOKIE", "jwt-auth")


class BearerJWTAuthentication(JWTAuthentication):
    """
    JWT Authentication for Bearer tokens (mobile/desktop apps).

    Validates that tokens have the correct audience claim ("app").
    Rejects tokens without audience or with incorrect audience.
    Also validates refresh tokens from request body.
    """

    def get_validated_token(self, raw_token):
        try:
            access_token = super().get_validated_token(raw_token)
        except AuthenticationFailed as exc:
            logger.error("Bearer token validation failed: %s", exc, exc_info=True)
            raise
        except Exception:
            logger.exception("Unexpected error validating bearer token.")
            raise

        # Check if 'aud' claim exists
        if "aud" not in access_token:
            logger.error('Bearer token missing required "aud" (audience) claim.')
            raise AuthenticationFailed('Token missing required "aud" (audience) claim')

        # Validate audience is "app"
        if access_token.get("aud") != "app":
            logger.error(
                'Invalid bearer token audience. Expected "app", got "%s".',
                access_token.get("aud"),
            )
            raise AuthenticationFailed(
                f'Invalid token audience. Expected "app", got "{access_token.get("aud")}"'
            )

        return access_token


class CookieJWTAuthenticationWithCSRF(JWTAuthentication):
    """
    JWT Authentication for cookie-based tokens (browser clients).

    Validates that tokens have the correct audience claim ("browser").
    Enforces CSRF protection for unsafe HTTP methods (POST, PUT, PATCH, DELETE).
    """

    def authenticate(self, request):
        try:
            # Skip if Authorization header is present (let BearerJWTAuthentication handle it)
            header = self.get_header(request)
            if header is not None:
                return None

            # Get token from cookie
            token = request.COOKIES.get(jwt_auth_cookie)

            if not token:
                return None

            # Validate token (signature, expiration, etc.)
            validated_token = self.get_validated_token(token)

            # Check if 'aud' claim exists
            if "aud" not in validated_token:
                logger.error(
                    'Cookie token missing required "aud" (audience) claim for %s.',
                    request.path,
                )
                raise AuthenticationFailed(
                    'Token missing required "aud" (audience) claim'
                )

            # Validate audience is "browser"
            if validated_token.get("aud") != "browser":
                logger.error(
                    'Invalid cookie token audience for %s. Expected "browser", got "%s".',
                    request.path,
                    validated_token.get("aud"),
                )
                raise AuthenticationFailed(
                    f'Invalid token audience. Expected "browser", got "{validated_token.get("aud")}"'
                )

            # Enforce CSRF protection for unsafe methods
            if request.method in ("POST", "PUT", "PATCH", "DELETE"):
                check_csrf(request)

            return self.get_user(validated_token), validated_token
        except AuthenticationFailed as exc:
            logger.error(
                "Cookie JWT authentication failed for %s: %s",
                request.path,
                exc,
                exc_info=True,
            )
            raise
        except Exception:
            logger.exception(
                "Unexpected error during cookie JWT authentication for %s.",
                request.path,
            )
            raise


class CustomRefreshTokenAuthentication(BaseAuthentication):
    """
    JWT Authentication for refresh tokens (browser clients).

    Validates that tokens have the correct audience claim ("browser").
    Enforces CSRF protection for unsafe HTTP methods (POST, PUT, PATCH, DELETE).
    """

    def authenticate(self, request):
        try:
            if client_type(request) == "browser":
                check_csrf(request)
                refresh_token_string = request.COOKIES.get(jwt_refresh_cookie)
                if not refresh_token_string:
                    logger.error(
                        "Refresh token authentication failed for %s: token missing from cookies.",
                        request.path,
                    )
                    raise AuthenticationFailed("No refresh token found in cookies")
                refresh_token = RefreshToken(refresh_token_string)
                if "aud" not in refresh_token:
                    logger.error(
                        "Refresh token missing 'aud' claim for %s (cookie-based).",
                        request.path,
                    )
                    raise AuthenticationFailed(
                        'Token missing required "aud" (audience) claim'
                    )
                if refresh_token.get("aud") != "browser":
                    logger.error(
                        "Invalid refresh token audience for %s. Expected 'browser', got '%s'.",
                        request.path,
                        refresh_token.get("aud"),
                    )
                    raise AuthenticationFailed(
                        f'Invalid token audience. Expected "app", got "{refresh_token.get("aud")}"'
                    )

            else:
                refresh_token_string = request.data.get("refresh")
                if not refresh_token_string:
                    logger.error(
                        "Refresh token authentication failed for %s: token missing from request body.",
                        request.path,
                    )
                    raise AuthenticationFailed(
                        "No refresh token found in request body or cookies"
                    )
                refresh_token = RefreshToken(refresh_token_string)
                if "aud" not in refresh_token:
                    logger.error(
                        "Refresh token missing 'aud' claim for %s (app-based).",
                        request.path,
                    )
                    raise AuthenticationFailed(
                        'Token missing required "aud" (audience) claim'
                    )
                if refresh_token.get("aud") != "app":
                    logger.error(
                        "Invalid app refresh token audience for %s. Expected 'app', got '%s'.",
                        request.path,
                        refresh_token.get("aud"),
                    )
                    raise AuthenticationFailed(
                        f'Invalid token audience. Expected "app", got "{refresh_token.get("aud")}"'
                    )

            return None
        except AuthenticationFailed as exc:
            logger.error(
                "Refresh token authentication failed for %s: %s",
                request.path,
                exc,
                exc_info=True,
            )
            raise
        except Exception:
            logger.exception(
                "Unexpected error during refresh token authentication for %s.",
                request.path,
            )
            raise
