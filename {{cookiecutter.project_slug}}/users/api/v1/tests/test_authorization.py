import pytest
from users.authentication import BearerJWTAuthentication, CookieJWTAuthenticationWithCSRF
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import AuthenticationFailed
from users.core import make_tokens
from rest_framework.test import APIRequestFactory
from django.conf import settings

access_cookie = settings.REST_AUTH.get('JWT_AUTH_COOKIE', 'jwt-auth')
refresh_cookie = settings.REST_AUTH.get('JWT_AUTH_REFRESH_COOKIE', 'jwt-refresh-token')

pytestmark = pytest.mark.django_db 

class TestAuthorization:
    def test_bearer_jwt_authentication(self, make_user):
        user = make_user
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token

        # Test: Token without 'aud' claim should fail
        with pytest.raises(AuthenticationFailed) as excinfo:
            BearerJWTAuthentication().get_validated_token(str(access))
        assert 'Token missing required "aud" (audience) claim' in str(excinfo.value)
        
        # Test: Token with 'aud' = 'app' should succeed
        access_app, _ = make_tokens(user, "app")
        validated_token = BearerJWTAuthentication().get_validated_token(str(access_app))
        assert validated_token.get('aud') == 'app'
        
        # Test: Token with 'aud' = 'browser' should fail for BearerJWTAuthentication
        access_browser, _ = make_tokens(user, "browser")
        with pytest.raises(AuthenticationFailed) as excinfo:
            BearerJWTAuthentication().get_validated_token(str(access_browser))
        assert 'Invalid token audience. Expected "app", got "browser"' in str(excinfo.value)


