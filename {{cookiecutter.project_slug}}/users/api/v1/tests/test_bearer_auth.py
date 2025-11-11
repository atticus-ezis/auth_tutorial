import pytest
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from allauth.account.models import EmailAddress, EmailConfirmationHMAC
from allauth.account.utils import user_pk_to_url_str
from allauth.account.forms import default_token_generator

from users.api.v1.tests.conftest import (
    app_output,
    get_login_response,
)

pytestmark = pytest.mark.django_db


class TestEndpoints:
    ####### reigster #######

    def test_registration_endpoint_app(
        self, api_client, register_data, registration_url
    ):
        response = api_client.post(
            registration_url,
            data=register_data,
            format="json",
            headers={"X-Client": "app"},
        )
        print(f"\nResponse Cookeis: {response.cookies}")
        print(f"\nResponse CSRF Token: {response.cookies.get('csrftoken_cookie')}")
        app_output(response, status.HTTP_201_CREATED)

    ####### login #######

    def test_login_endpoint_app(self, make_user, api_client, login_url):
        user, password = make_user

        login_data = {
            "username": user.username,
            "password": password,
        }

        print(f"\nCookies BEFORE request: {api_client.cookies}")

        response = api_client.post(
            login_url, data=login_data, format="json", headers={"X-Client": "app"}
        )

        app_output(response, status.HTTP_200_OK)

    ####### refresh #######

    def test_refresh_endpoint_app_with_aud(
        self, make_user, api_client, refresh_url, login_url
    ):
        user, _ = make_user
        refresh_token = RefreshToken.for_user(user)
        refresh_token["aud"] = "app"
        refresh = str(refresh_token)

        refresh_response = api_client.post(
            refresh_url,
            data={"refresh": refresh},
            format="json",
            headers={"X-Client": "app"},
        )

        app_output(refresh_response, status.HTTP_200_OK)

    def test_refresh_endpoint_app_without_aud(
        self, make_user, api_client, refresh_url, login_url
    ):
        user, _ = make_user
        refresh_token = RefreshToken.for_user(user)
        refresh = str(refresh_token)

        refresh_response = api_client.post(
            refresh_url,
            data={"refresh": refresh},
            format="json",
            headers={"X-Client": "app"},
        )

        assert refresh_response.status_code == status.HTTP_401_UNAUTHORIZED
        assert 'Token missing required "aud" (audience) claim' in str(
            refresh_response.data["detail"]
        )

    ####### logout #######

    def test_logout_endpoint_app(self, make_user, api_client, logout_url, login_url):
        user, password = make_user
        login_response = get_login_response(
            api_client, login_url, user.username, password, client="app"
        )

        access_token = login_response.data.get("access")
        refresh_token = login_response.data.get("refresh")

        logout_response = api_client.post(
            logout_url,
            data={"refresh": refresh_token},
            format="json",
            headers={"Authorization": f"Bearer {access_token}", "X-Client": "app"},
        )

        assert logout_response.status_code == status.HTTP_200_OK
        assert logout_response.data.get("detail") == "Successfully logged out."

        try:
            RefreshToken(refresh_token)
            assert False, "Blacklisted refresh token should raise TokenError"
        except TokenError:
            pass

    ####### password change #######

    def test_password_change_endpoint_app(
        self, make_user, api_client, password_change_url, login_url
    ):
        user, password = make_user

        login_response = get_login_response(
            api_client, login_url, user.username, password, client="app"
        )

        access_token = login_response.data.get("access")

        password_change_response = api_client.post(
            password_change_url,
            data={
                "old_password": password,
                "new_password1": "NewPassword123!",
                "new_password2": "NewPassword123!",
            },
            format="json",
            headers={"X-Client": "app", "Authorization": f"Bearer {access_token}"},
        )
        assert (
            password_change_response.status_code == status.HTTP_200_OK
        ), f"status coode is {password_change_response.status_code} and data is {password_change_response.data}"
        app_output(password_change_response, status.HTTP_200_OK)

    ####### email confirm #######

    def test_confirm_email_endpoint_app(
        self, api_client, confirm_email_url, register_data, registration_url
    ):
        """Test email confirmation for app client."""
        # Register user (creates email confirmation)
        registration_response = api_client.post(
            registration_url,
            data=register_data,
            format="json",
            headers={"X-Client": "app"},
        )
        assert registration_response.status_code == status.HTTP_201_CREATED

        email_address = EmailAddress.objects.get(email=register_data["email"])
        email_confirmation = EmailConfirmationHMAC(email_address)
        key = email_confirmation.key

        # Confirm email
        response = api_client.post(
            confirm_email_url,
            data={"key": key},
            format="json",
            headers={"X-Client": "app"},
        )

        app_output(response, status.HTTP_200_OK)

    ####### password reset confirm #######

    def test_password_reset_confirm_endpoint_app(
        self, make_user, api_client, password_reset_confirm_url
    ):
        """Test password reset confirm for app client."""
        user, _ = make_user

        uid = user_pk_to_url_str(user)
        token = default_token_generator.make_token(user)

        # Reset password
        response = api_client.post(
            password_reset_confirm_url,
            data={
                "uid": uid,
                "token": token,
                "new_password1": "NewPassword123!",
                "new_password2": "NewPassword123!",
            },
            format="json",
            headers={"X-Client": "app"},
        )

        app_output(response, status.HTTP_200_OK)

    #### user details #######

    def test_user_details_endpoint_app(
        self, make_user, api_client, user_details_url, login_url
    ):
        """Test that app clients can update user details using bearer tokens."""
        user, password = make_user

        login_response = get_login_response(
            api_client,
            login_url,
            user.username,
            password,
            client="app",
        )

        payload = {"username": "appuser"}
        response = api_client.patch(
            user_details_url,
            data=payload,
            format="json",
            headers={
                "X-Client": "app",
                "Authorization": f"Bearer {login_response.data.get('access')}",
            },
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.data.get("username") == payload["username"]

        user.refresh_from_db()
        assert user.username == payload["username"]
