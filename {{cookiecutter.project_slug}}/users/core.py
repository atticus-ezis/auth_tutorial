from rest_framework.exceptions import PermissionDenied
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import ValidationError
from django.middleware.csrf import (
    CSRF_TOKEN_LENGTH,
    _check_token_format,
    _unmask_cipher_token,
    InvalidTokenFormat,
)
from django.utils.crypto import constant_time_compare

# Usefule helper functions


def make_tokens(user, aud):
    refresh = RefreshToken.for_user(user)
    refresh["aud"] = aud
    access = refresh.access_token
    access["aud"] = aud
    return access, refresh


def _normalise_csrf_token(token, source):
    """
    Convert a potentially masked CSRF token to its underlying secret.
    Raises PermissionDenied if the token has an invalid format.
    """
    if not token:
        return ""

    try:
        _check_token_format(token)
    except InvalidTokenFormat as exc:
        raise PermissionDenied(f"CSRF token from {source} {exc.reason}.")

    if len(token) == CSRF_TOKEN_LENGTH:
        return _unmask_cipher_token(token)

    return token


def check_csrf(request):
    """
    Check CSRF token using double-submit cookie pattern.
    Accepts either masked or unmasked tokens and compares secrets in constant time.
    """
    csrf_token_header = request.META.get("HTTP_X_CSRFTOKEN", "")
    csrf_token_cookie = request.COOKIES.get(settings.CSRF_COOKIE_NAME, "")

    if not csrf_token_header:
        raise PermissionDenied("CSRF token missing from header.")

    if not csrf_token_cookie:
        raise PermissionDenied("CSRF token missing from cookie.")

    header_secret = _normalise_csrf_token(csrf_token_header, "header")
    cookie_secret = _normalise_csrf_token(csrf_token_cookie, "cookie")

    if not header_secret or not cookie_secret:
        raise PermissionDenied("CSRF token missing or invalid.")

    if not constant_time_compare(header_secret, cookie_secret):
        raise PermissionDenied("CSRF token mismatch.")


def client_type(request):
    allowed_types = ["browser", "app"]
    client_type = request.headers.get("X-Client", "").lower().strip()
    if not client_type:
        return "browser"
    if client_type not in allowed_types:
        raise ValidationError(
            {
                "detail": [
                    f"Invalid client type. expected {allowed_types}, got '{client_type}'."
                ]
            }
        )
    return client_type


def require_auth_type(request):
    auth_type = request.headers.get("X-Client")
    if not auth_type:
        raise ValidationError({"detail": ["Missing X-Client header."]})
    if auth_type not in ["browser", "app"]:
        raise ValidationError(
            {
                "detail": [
                    "Invalid authentication type. expected 'browser' or 'app', got '{auth_type}'."
                ]
            }
        )
    return auth_type
