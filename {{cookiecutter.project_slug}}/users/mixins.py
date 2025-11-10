from django.conf import settings
from django.middleware import csrf
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from users.core import client_wants_app_tokens, make_tokens

import logging

logger = logging.getLogger(__name__)

jwt_auth_cookie = settings.REST_AUTH.get("JWT_AUTH_COOKIE", "jwt-auth")
jwt_refresh_cookie = settings.REST_AUTH.get(
    "JWT_AUTH_REFRESH_COOKIE", "jwt-refresh-token"
)
csrf_cookie_name = settings.CSRF_COOKIE_NAME


class HybridAuthMixin:
    """
    Mixin that adapts JWT token delivery based on client type (X-Client header).

    - X-Client: app → Returns tokens in JSON body
    - No X-Client header → Returns tokens in HttpOnly cookies (browser)

    Works with dj-rest-auth views that already create tokens in their response.
    The mixin extracts existing tokens and formats them appropriately.
    """

    def _response_data(self, response):
        data = getattr(response, "data", None)
        return data if isinstance(data, dict) else None

    def _clear_response_tokens(self, response):
        data = self._response_data(response)
        if data:
            data.pop("access", None)
            data.pop("refresh", None)
        return data

    def _delete_cookies(self, response, *names):
        for name in names:
            if response.cookies.get(name):
                response.delete_cookie(name)
                try:
                    del response.cookies[name]
                except KeyError:
                    pass

    def issue_for_browser(self, request, response, access, refresh):
        data = self._clear_response_tokens(response)
        if not access or not refresh:
            return response

        response.set_cookie(jwt_auth_cookie, str(access))
        response.set_cookie(jwt_refresh_cookie, str(refresh))

        csrf.get_token(request)
        if data is not None:
            data.update(
                {
                    "authType": "cookie",
                    "csrfToken": request.META.get("CSRF_COOKIE", ""),
                }
            )
        return response

    def issue_for_app(self, response, access, refresh):
        data = self._response_data(response)
        if not access or not refresh:
            if data is not None:
                data.pop("access", None)
                data.pop("refresh", None)
            return response

        expires_in = (
            int(access.lifetime.total_seconds())
            if getattr(access, "lifetime", None)
            else None
        )
        if data is not None:
            data.update(
                {
                    "access": str(access),
                    "refresh": str(refresh),
                    "expires_in": expires_in,
                    "authType": "bearer",
                }
            )

        self._delete_cookies(
            response,
            jwt_auth_cookie,
            jwt_refresh_cookie,
            csrf_cookie_name,
            "csrftoken",
            "csrftoken_cookie",
        )
        return response

    def _validate_token_has_aud(self, token_str, expected_aud):
        if not token_str:
            return False

        token = None
        for token_cls in (AccessToken, RefreshToken):
            try:
                token = token_cls(token_str)
                break
            except TokenError:
                continue
        if token is None:
            return False
        try:
            return token.get("aud") == expected_aud
        except Exception:
            logger.exception("Failed to validate JWT token %s", token_str)
            return False

    def _blacklist_refresh_token(self, token_str):
        """
        Attempt to blacklist the provided refresh token.
        Silently ignores failures when blacklist app is not enabled or
        token is already invalid/expired.
        """
        if not token_str:
            return

        try:
            refresh_token = RefreshToken(token_str)
            blacklist = getattr(refresh_token, "blacklist", None)
            if callable(blacklist):
                blacklist()
        except TokenError:
            logger.debug("Refresh token already invalid; skipping blacklist.")
        except AttributeError:
            logger.debug("Token blacklist not available; skipping blacklist.")
        except Exception:
            logger.exception("Failed to blacklist refresh token.")

    def _get_user_from_response(self, response):
        user = getattr(self, "user", None)
        if getattr(user, "is_authenticated", False):
            return user

        data = self._response_data(response)
        if not data:
            return None

        user_data = data.get("user")
        if not isinstance(user_data, dict):
            return None

        user_id = user_data.get("id") or user_data.get("pk")
        if not user_id:
            return None

        from django.contrib.auth import get_user_model

        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def _get_user_from_tokens(self, access, refresh):
        token = None
        try:
            if refresh:
                token = RefreshToken(refresh)
            elif access:
                token = AccessToken(access)
        except TokenError:
            return None
        except Exception:
            logger.exception("Failed to decode JWT token for user lookup.")
            return None

        user_id = token.get("user_id") if token else None
        if not user_id:
            return None

        from django.contrib.auth import get_user_model

        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def _extract_tokens(self, response):
        data = self._response_data(response) or {}
        access = data.get("access")
        refresh = data.get("refresh")

        if not (access and refresh):
            access_cookie = response.cookies.get(jwt_auth_cookie)
            refresh_cookie = response.cookies.get(jwt_refresh_cookie)
            access = access or getattr(access_cookie, "value", None)
            refresh = refresh or getattr(refresh_cookie, "value", None)

        return access, refresh

    def _get_or_issue_tokens_from_response(self, request, response, expected_aud):
        access, refresh = self._extract_tokens(response)
        user = self._get_user_from_response(response)

        request_user = getattr(request, "user", None)
        if getattr(request_user, "is_authenticated", False):
            user = request_user

        if not user:
            user = self._get_user_from_tokens(access, refresh)

        if not user:
            return (access, refresh) if access and refresh else (None, None)

        if refresh:
            self._blacklist_refresh_token(refresh)

        return make_tokens(user, expected_aud)

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
        if response.status_code not in (200, 201):
            return response

        is_app = client_wants_app_tokens(request)
        expected_aud = "app" if is_app else "browser"

        access, refresh = self._get_or_issue_tokens_from_response(
            request, response, expected_aud
        )
        if not access or not refresh:
            return response

        return (
            self.issue_for_app(response, access, refresh)
            if is_app
            else self.issue_for_browser(request, response, access, refresh)
        )
