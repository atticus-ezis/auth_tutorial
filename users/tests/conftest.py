"""
Pytest fixtures for authentication tests
"""
import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status
from allauth.account.models import EmailAddress
from allauth.account.models import EmailConfirmationHMAC
from django.contrib.auth.tokens import default_token_generator
from allauth.account.utils import user_pk_to_url_str
from allauth.account.forms import default_token_generator as allauth_token_generator

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
def frontend_url():
    """Frontend URL for testing"""
    from django.conf import settings
    return settings.FRONTEND_URL.rstrip('/')




@pytest.fixture
def logout_url():
    """Logout URL for testing"""
    return '/api/v1/auth/logout/'

@pytest.fixture
def login_url():
    """Login URL for testing"""
    return '/api/v1/auth/login/'


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
        authType = data.get('authType')
        access_token = data.get('access')
        refresh_token = data.get('refresh')
        assert access_token is not None, "Access token should be set"
        assert refresh_token is not None, "Refresh token should be set"
        assert authType == 'bearer', "Auth type should be bearer"
        return {
            'access_token': access_token,
            'refresh_token': refresh_token
        }

def assert_browser_auth_response(response, expected_status=200):

    assert response.status_code == expected_status
    
    # Check that tokens are in cookies, not response body
    assert 'access' not in response.data, "Access token should not be in response data"
    assert 'refresh' not in response.data, "Refresh token should not be in response data"
    authType = response.data.get('authType')
    assert authType == 'cookie', "Auth type should be cookie"
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

@pytest.fixture
def create_user_with_email():
    """Create a user with email verification and password reset tokens."""
    # Clear any existing users to avoid conflicts
    User.objects.all().delete()
    
    existing_user = User.objects.create_user(
        username='DummyUser',
        password='TestPass4321',
        email='example.email@gmail.com'
    )

    email_address = EmailAddress.objects.create(
        user=existing_user,  
        email=existing_user.email,
        verified=False
    )

    email_confirmation = EmailConfirmationHMAC(email_address)
    key = email_confirmation.key    
    uid = user_pk_to_url_str(existing_user)
    token = allauth_token_generator.make_token(existing_user)

    return {
        'user': existing_user,
        'key': key,
        'uid': uid,
        'token': token,
        'email': email_address,
    }