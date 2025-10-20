"""
Pytest fixtures for authentication tests
"""
import pytest
from django.contrib.auth import get_user_model
from django.core import mail
from rest_framework.test import APIClient
import re

User = get_user_model()


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
    
    # Alternative: password reset pattern
    match = re.search(r'http://localhost:3000/password-reset/([A-Za-z0-9\-_:]+)', email_body)
    if match:
        return match.group(1)
    
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

