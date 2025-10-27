"""
Pytest fixtures for authentication tests
"""
import pytest
from django.contrib.auth import get_user_model
from django.core import mail
from rest_framework.test import APIClient
import re
from rest_framework import status

# Set email backend for all tests
pytestmark = pytest.mark.django_db

BASE_URL = "http://localhost:8000"

User = get_user_model()

@pytest.fixture(autouse=True)
def email_backend():
    """Automatically set locmem email backend for all tests"""
    from django.conf import settings
    settings.EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'

@pytest.fixture
def frontend_url():
    """Frontend URL"""
    return BASE_URL

@pytest.fixture
def api_client():
    """Provide an API client for testing"""
    return APIClient()


@pytest.fixture
def user_data():
    """Provide standard user registration data"""
    return {
        'username': 'testuser',
        'email': 'test@example.com',
        'password1': 'TestPassword123!',
        'password2': 'TestPassword123!',
    }


@pytest.fixture
def registration_url():
    """Registration endpoint URL"""
    return '/api/v1/auth/registration/'


@pytest.fixture
def verify_email_url():
    """Email verification endpoint URL"""
    return '/api/v1/auth/registration/account-confirm-email/'


@pytest.fixture
def resend_email_url():
    """Resend email verification endpoint URL"""
    return '/api/v1/auth/registration/resend-email/'


@pytest.fixture
def password_reset_url():
    """Password reset request endpoint URL"""
    return '/api/v1/auth/password/reset/'


@pytest.fixture
def password_reset_confirm_url():
    """Password reset confirm endpoint URL"""
    return '/api/v1/auth/password/reset/confirm/'


@pytest.fixture
def user_details_url():
    """User details endpoint URL"""
    return '/api/v1/auth/user/'


@pytest.fixture
def clear_mailbox():
    """Clear the email outbox before each test"""
    mail.outbox = []
    yield
    mail.outbox = []
    
def extract_verification_key_from_email(email_body):
    """
    Extract the verification key from the email body.
    The key is in a URL like: http://localhost:3000/verify-email/KEY
    """
    # Look for the frontend URL with verification key (from CustomAccountAdapter)
    match = re.search(r'http://localhost:3000/verify-email/([A-Za-z0-9\-_:]+)', email_body)
    if match:
        return match.group(1)
    
    # Alternative: password reset pattern - URL format: password-reset/{uid}/{token}/
    match = re.search(r'http://localhost:3000/password-reset/([A-Za-z0-9\-_:]+)/([A-Za-z0-9\-_:]+)', email_body)
    if match:
        return {'uid': match.group(1), 'token': match.group(2)}
    
    # Pattern with ? key parameter
    match = re.search(r'[?&]key=([A-Za-z0-9\-_:]+)', email_body)
    if match:
        return match.group(1)
    
    # Last resort: look for HMAC key pattern
    match = re.search(r'([A-Za-z0-9]+:[A-Za-z0-9\-]{20,})', email_body)
    if match:
        return match.group(1)
        
    return None



@pytest.fixture
def key_extractor():
    """Provide a function to extract keys from emails"""
    return extract_verification_key_from_email


@pytest.fixture
def frontend_url():
    """Frontend URL for testing"""
    from django.conf import settings
    return settings.FRONTEND_URL.rstrip('/')


@pytest.fixture(scope="class")
def registered_user_data():
    """User data that persists across the test class"""
    return {
        'username': 'testuser',
        'email': 'test@example.com',
        'password1': 'TestPassword123!',
        'password2': 'TestPassword123!',
    }

@pytest.fixture(scope="class")
def registered_user_cookies():
    """Return empty cookies - will be populated by the first test"""
    return {}


@pytest.fixture
def logout_url():
    """Logout URL for testing"""
    return '/api/v1/auth/logout/'

@pytest.fixture
def login_url():
    """Login URL for testing"""
    return '/api/v1/auth/login/'

@pytest.fixture
def resend_email_url():
    return '/api/v1/auth/registration/resend-email/'

@pytest.fixture
def verify_email_url():
    return '/api/v1/auth/registration/account-confirm-email/'

@pytest.fixture
def refresh_url():
    return '/api/v1/auth/token/refresh/'


def assert_app_auth_response(response):

        cookies = response.cookies
        access = cookies.get('jwt-auth') or cookies.get('access')
        refresh = cookies.get('jwt-refresh-token') or cookies.get('refresh')
        assert access is None, "JWT access cookie should not be set"
        assert refresh is None, "JWT refresh cookie should not be set"
        data = response.json()
        access_token = data.get('access')
        refresh_token = data.get('refresh')
        assert access_token is not None, "Access token should be set"
        assert refresh_token is not None, "Refresh token should be set"
        return {
            'access_token': access_token,
            'refresh_token': refresh_token
        }

def assert_browser_auth_response(response, expected_status=200):
    """
    Helper function to assert that a response from a browser request has the correct format.
    
    Args:
        response: The response object to check
        expected_status: Expected HTTP status code (default: 200)
    
    Returns:
        dict: Contains 'csrf_token' from response data for use in subsequent requests
    """
    assert response.status_code == expected_status
    
    # Check that tokens are in cookies, not response body
    assert 'access' not in response.data, "Access token should not be in response data"
    assert 'refresh' not in response.data, "Refresh token should not be in response data"
    
    # Check that cookies are set
    cookies = response.cookies
    assert 'jwt-auth' in cookies, "JWT access cookie should be set"
    assert 'jwt-refresh-token' in cookies, "JWT refresh cookie should be set"
    assert 'csrftoken' in cookies, "CSRF token cookie should be set"
    
    # Check CSRF token consistency
    csrf_token_cookie = cookies['csrftoken'].value
    csrf_token_body = response.data.get('csrf_token')
    assert csrf_token_body is not None, "CSRF token should be in response data"
    assert csrf_token_body == csrf_token_cookie, f"CSRF token should be the same {csrf_token_body} != {csrf_token_cookie}"
    
    return {
        'csrf_token': csrf_token_body,
        'refresh_token': cookies['jwt-refresh-token'].value
    }


def assert_missing_csrf_token_fails(response):
    """
    Helper function to assert that a response without CSRF token was rejected.
    
    Args:
        response: The response object to check
    """
    assert response.status_code == status.HTTP_403_FORBIDDEN, \
        f"Request without CSRF token should be rejected, got status {response.status_code}"
    assert 'CSRF' in str(response.json().get('detail', '')).upper(), \
        f"Error should mention CSRF, got: {response.json()}"

