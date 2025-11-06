import pytest
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework import status
from django.conf import settings

pytestmark = pytest.mark.django_db 

access_cookie = settings.REST_AUTH.get('JWT_AUTH_COOKIE', 'jwt-auth')
refresh_cookie = settings.REST_AUTH.get('JWT_AUTH_REFRESH_COOKIE', 'jwt-refresh-token')

@pytest.fixture
def make_user():
    user = User.objects.create_user(username='testuser', password='testpassword', email='testuser@example.com')
    return user, 'testpassword'

@pytest.fixture
def register_data():
    """Provide standard user registration data"""
    return {
        'username': 'testuser',
        'email': 'test@example.com',
        'password1': 'TestPassword123!',
        'password2': 'TestPassword123!',
    }

@pytest.fixture
def api_client():
    """Provide an API client for testing"""
    return APIClient()

@pytest.fixture
def registration_url():
    """Registration URL"""
    return '/api/v1/auth/registration/'

@pytest.fixture
def login_url():
    """Login URL"""
    return '/api/v1/auth/login/'

@pytest.fixture
def refresh_url():
    """Refresh URL"""
    return '/api/v1/auth/token/refresh/'

@pytest.fixture
def logout_url():
    """Logout URL"""
    return '/api/v1/auth/logout/'

@pytest.fixture
def confirm_email_url():
    """Email confirmation URL"""
    return '/api/v1/auth/registration/account-confirm-email/'

@pytest.fixture
def password_reset_confirm_url():
    """Password reset confirm URL"""
    return '/api/v1/auth/password/reset/confirm/'


def browser_output(response, expected_status):
    # body check
    assert response.status_code == expected_status, f"Login failed with status code {response.status_code}, {response.data}"
    data = response.data 
    access = data.get("access")
    refresh = data.get("refresh")
    csrf_body = data.get("csrftoken_body")
    auth_type = data.get("authType")
    assert not access or not refresh
    assert auth_type == "cookie"
    assert csrf_body is not None, "CSRF token should be in response data"

    # cookie check
    cookies = response.cookies 
    access_raw = cookies.get(access_cookie) 
    refresh_raw = cookies.get(refresh_cookie)
    access = AccessToken(access_raw.value)
    refresh = RefreshToken(refresh_raw.value)
    csrf_cookie = cookies.get("csrftoken_cookie")
    assert access.get('aud') == "browser", "JWT access cookie should have browser audience"
    assert refresh.get('aud') == "browser", "JWT refresh cookie should have browser audience"
    assert csrf_cookie.value == csrf_body, "CSRFs tokens should match"

def app_output(response, expected_status):
    # body check
    assert response.status_code == expected_status, f"Login failed with status code {response.status_code}, {response.data}"
    data = response.data 
    access_raw = data.get("access")
    refresh_raw = data.get("refresh")
    access = AccessToken(access_raw)
    refresh = RefreshToken(refresh_raw)
    csrf_body = data.get("csrftoken_body")
    auth_type = data.get("authType")
    assert access and refresh
    assert auth_type == "bearer"
    assert csrf_body is None, "CSRF token should not be in response data"
    assert access.get('aud') == "app", "JWT access token should have app audience"
    assert refresh.get('aud') == "app", "JWT refresh token should have app audience"

    # cookies check
    cookies = response.cookies 
    assert cookies.get(access_cookie) is None, "JWT access token should not be in response cookies"
    assert cookies.get(refresh_cookie) is None, "JWT refresh token should not be in response cookies"
    assert cookies.get("csrftoken_cookie") is None, "CSRF token should not be in response cookies"


def get_login_response(api_client, login_url, username, password, client='browser', csrf_token=None):
        # Only clear cookies if we're not providing a CSRF token
        # (CSRF double-submit requires both cookie and header to match)
        if not csrf_token:
            api_client.cookies.clear()
        
        headers = {'X-Client': client}
        if csrf_token:
            headers['X-CSRFToken'] = csrf_token
        
        login_response = api_client.post(
            login_url,
            data={'username': username, 'password': password},
            format='json',
            headers=headers
        )
        return login_response