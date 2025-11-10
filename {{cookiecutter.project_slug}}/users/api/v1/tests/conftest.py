import pytest
from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from django.conf import settings
from django.core.cache import cache

pytestmark = pytest.mark.django_db

access_cookie = settings.REST_AUTH.get("JWT_AUTH_COOKIE", "jwt-auth")
refresh_cookie = settings.REST_AUTH.get("JWT_AUTH_REFRESH_COOKIE", "jwt-refresh-token")
csrf_cookie_name = settings.CSRF_COOKIE_NAME


@pytest.fixture
def make_user():
    user = User.objects.create_user(
        username="testuser", password="testpassword", email="testuser@example.com"
    )
    return user, "testpassword"


@pytest.fixture
def register_data():
    """Provide standard user registration data"""
    return {
        "username": "testuser",
        "email": "testuser@example.com",
        "password1": "testpassword",
        "password2": "testpassword",
    }


@pytest.fixture
def api_client():
    """Provide an API client for testing"""
    return APIClient()


@pytest.fixture
def registration_url():
    """Registration URL"""
    return reverse("rest_register")


@pytest.fixture
def login_url():
    """Login URL"""
    return reverse("rest_login")


@pytest.fixture
def refresh_url():
    """Refresh URL"""
    return reverse("rest_token_refresh")


@pytest.fixture
def logout_url():
    """Logout URL"""
    return reverse("rest_logout")


@pytest.fixture
def confirm_email_url():
    """Email confirmation URL"""
    return reverse("account_confirm_email_api")


@pytest.fixture
def resend_email_url():
    """Resend email URL"""
    return reverse("resend_email")


@pytest.fixture
def reset_password_url():
    """Reset password URL"""
    return reverse("rest_password_reset")


@pytest.fixture
def resend_password_email_url():
    """Resend password email URL"""
    return reverse("resend_password_email")


@pytest.fixture
def password_reset_confirm_url():
    """Password reset confirm URL"""
    return reverse("password_reset_confirm_api")


@pytest.fixture
def user_details_url():
    """User details URL"""
    return reverse("user_details")


@pytest.fixture
def password_change_url():
    return reverse("rest_password_change")


@pytest.fixture(autouse=True)
def clear_throttle_cache():
    """
    Reset throttle history before each test so scoped throttles
    don't accumulate across the suite.
    """
    cache.clear()
    yield
    cache.clear()


def browser_output(response, expected_status):
    # body check
    assert (
        response.status_code == expected_status
    ), f"Login failed with status code {response.status_code}, {response.data}"
    data = response.data
    access = data.get("access")
    refresh = data.get("refresh")
    auth_type = data.get("authType")
    assert not access or not refresh
    assert auth_type == "cookie"
    # cookie check
    cookies = response.cookies
    access_raw = cookies.get(access_cookie)
    refresh_raw = cookies.get(refresh_cookie)
    access = AccessToken(access_raw.value)
    refresh = RefreshToken(refresh_raw.value)
    csrf_cookie = cookies.get("csrftoken_cookie")
    assert (
        access.get("aud") == "browser"
    ), "JWT access cookie should have browser audience"
    assert (
        refresh.get("aud") == "browser"
    ), "JWT refresh cookie should have browser audience"
    assert csrf_cookie is not None, "CSRF token should be in response cookies"
    csrf_body = data.get("csrfToken")
    assert csrf_body == csrf_cookie.value, "CSRF token value mismatch"


def app_output(response, expected_status):
    # body check
    assert (
        response.status_code == expected_status
    ), f"Login failed with status code {response.status_code}, {response.data}"
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
    assert access.get("aud") == "app", "JWT access token should have app audience"
    assert refresh.get("aud") == "app", "JWT refresh token should have app audience"

    # cookies check
    cookies = response.cookies
    assert (
        cookies.get(access_cookie) is None
    ), "JWT access token should not be in response cookies"
    assert (
        cookies.get(refresh_cookie) is None
    ), "JWT refresh token should not be in response cookies"
    assert (
        cookies.get(csrf_cookie_name) is None
    ), "CSRF token should not be in response cookies"


def get_login_response(
    api_client, login_url, username, password, client="browser", csrf_token=None
):
    # Only clear cookies if we're not providing a CSRF token
    # (CSRF double-submit requires both cookie and header to match)
    if not csrf_token:
        api_client.cookies.clear()

    headers = {"X-Client": client}
    if csrf_token:
        headers["X-CSRFToken"] = csrf_token

    login_response = api_client.post(
        login_url,
        data={"username": username, "password": password},
        format="json",
        headers=headers,
    )
    return login_response


def get_csrf_token(api_client, url=login_url, username="username", password="password"):
    response = get_login_response(
        api_client,
        url,
        username,
        password,
        client="browser",
    )

    csrf_cookie = response.cookies.get(csrf_cookie_name)
    assert csrf_cookie is not None, "CSRF token should be set in cookies"
    return csrf_cookie.value
