# register a new user with an 'origin' header
# check that cookies are set. test that csrf token double submit works for a protected endpoint.

import pytest
import json
from rest_framework import status
import requests
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import mail
from allauth.account.models import EmailAddress
from users.tests.conftest import assert_browser_auth_response, assert_missing_csrf_token_fails, assert_app_auth_response
User = get_user_model()


pytestmark = pytest.mark.django_db


# Test checks
# When a browser request is made...
# response body doesn't include tokens
# cookies are set with csrf + jwt tokens
# csrf tokens are required for protected endpoints

class TestHybridAuth:

    def test_app_auth_flow(
        self, 
        api_client, 
        user_data, 
        registration_url, 
        logout_url, 
        login_url, 
        refresh_url, 
        user_details_url,
    ):
        """Test complete simplejwt-based auth flow: register, CSRF protection, and logout"""
        
        #### register
        response = api_client.post(
            registration_url,
            data=user_data,
            format='json',
        )
        assert response.status_code == status.HTTP_201_CREATED
        tokens = assert_app_auth_response(response)
        refresh_token = tokens['refresh_token']
        
        #### refresh 
        refresh_response = api_client.post(
            refresh_url,
            data={'refresh': refresh_token},
            format='json',
        )
        assert refresh_response.status_code == status.HTTP_200_OK
        refresh_tokens = assert_app_auth_response(refresh_response)
        refresh_token = refresh_tokens['refresh_token']
        fresh_access_token = refresh_tokens['access_token']

        #### unprotected endpoint - clear cookies to test without authentication
        api_client.cookies.clear()
        unprotected_response = api_client.patch(
            user_details_url,
            format='json',
            data={
                'username': 'NewUsername'
            },
        )
        assert unprotected_response.status_code == status.HTTP_401_UNAUTHORIZED
        
        # protected
        protected_response = api_client.patch(
            user_details_url,
            format='json',
            HTTP_AUTHORIZATION=f'Bearer {fresh_access_token}',
            data={
                'username': 'NewUsername'
            },
        )
        assert protected_response.status_code == status.HTTP_200_OK
        assert protected_response.data['username'] == "NewUsername", "Username should be updated"
        updated_user = User.objects.get(username="NewUsername")
        assert updated_user is not None, "Updated user should be found in database"

        #### logout
        logout_response = api_client.post(
            logout_url,
            data={"refresh": refresh_token},
            format='json',
            # HTTP_AUTHORIZATION=f'Bearer {fresh_access_token}',
        )
        assert logout_response.status_code == status.HTTP_200_OK
        assert 'logged out' in logout_response.json()['detail'].lower()
        try:
            RefreshToken(refresh_token)
            assert False, "Token should be blacklisted after logout"
        except TokenError as e:
            assert "blacklisted" in str(e).lower()

        #### login 
        login_response = api_client.post(
            login_url,
            data={
                'username': 'NewUsername', 
                'password': user_data['password1']
            },
            format='json',
        )
        assert login_response.status_code == status.HTTP_200_OK
        login_tokens = assert_app_auth_response(login_response)
        refresh_token = login_tokens['refresh_token']


    
    def test_browser_auth_flow(
            self, 
            api_client, 
            user_data, 
            registration_url, 
            logout_url,
            frontend_url, 
            login_url, 
            user_details_url,
            refresh_url,
        ):
        """Test complete cookie-based auth flow: register, CSRF protection, and logout"""
        
        #### register 
        response = api_client.post(
            registration_url,
            data=user_data,
            format='json',
            HTTP_ORIGIN=frontend_url,
            HTTP_CONTENT_TYPE='application/json'
        )
        
        auth_data = assert_browser_auth_response(response, status.HTTP_201_CREATED)
        refresh_token = auth_data['refresh_token']
        
        #### logout 
        response_no_csrf = api_client.post(
            logout_url,
            data={},
            format='json',
            HTTP_ORIGIN=frontend_url
            # No HTTP_X_CSRFTOKEN!
        )
        assert response_no_csrf.status_code == status.HTTP_200_OK
        assert 'logged out' in response_no_csrf.json()['detail'].lower()
        try:
            RefreshToken(refresh_token)
            assert False, "Token should be blacklisted after logout"
        except TokenError as e:
            assert "blacklisted" in str(e).lower()

        ################################

        # Step 5: Login again with fresh credentials
        api_client.cookies.clear()
   
        login_response = api_client.post(
            login_url,
            data={
                'username': user_data['username'], 
                'password': user_data['password1']
            },
            format='json',
            HTTP_ORIGIN=frontend_url,
        )
        
        assert login_response.status_code == status.HTTP_200_OK, \
            f"Login failed: {login_response.json()}"
        
        login_auth_data = assert_browser_auth_response(login_response)
        login_csrf_token = login_auth_data['csrf_token']

        ################################

        # Step 6: Test CSRF protection on protected endpoint

        # WITHOUT CSRF token
        protected_response_no_csrf = api_client.patch(
            user_details_url,
            data={"username": "TestUser2"},
            format='json',
            HTTP_ORIGIN=frontend_url,
            # No HTTP_X_CSRFTOKEN!
        )

        assert_missing_csrf_token_fails(protected_response_no_csrf)
        
        # WITH CSRF token - should succeed
        protected_response_with_csrf = api_client.patch(
            user_details_url,
            data={"username": "TestUser2"},
            format='json',
            HTTP_ORIGIN=frontend_url,
            HTTP_X_CSRFTOKEN=login_csrf_token
        )
        assert protected_response_with_csrf.status_code == status.HTTP_200_OK, \
            f"Protected endpoint should succeed with CSRF token: {protected_response_with_csrf.json()}"  
        assert protected_response_with_csrf.data['username'] == "TestUser2", "Username should be updated"
        updated_user = User.objects.get(username="TestUser2")
        assert updated_user is not None, "Updated user should be found in database"

        ####### test refresh token

        refresh_response_no_csrf = api_client.post(
            refresh_url,
            data={},
            format='json',
            HTTP_ORIGIN=frontend_url,
            # No HTTP_X_CSRFTOKEN
        )
        assert_missing_csrf_token_fails(refresh_response_no_csrf)

        refresh_response_with_csrf = api_client.post(
            refresh_url,
            data={},
            format='json',
            HTTP_ORIGIN=frontend_url,
            HTTP_X_CSRFTOKEN=login_csrf_token
        )

        assert refresh_response_with_csrf.status_code == status.HTTP_200_OK, \
            f"Protected endpoint should succeed with CSRF token: {refresh_response_with_csrf.json()}"

# @pytest.mark.django_db(transaction=True)
class TestEmailLinks:
    def test_browser_email_links(
        self, 
        api_client, 
        user_data, 
        registration_url, 
        logout_url, 
        frontend_url, 
        login_url, 
        mailoutbox, 
        resend_email_url,
        verify_email_url,
        key_extractor,
        password_reset_url,
        password_reset_confirm_url,
    ):
        """Test email link verification flow: register, email link, login, and logout"""
        new_user_data = {
            "username": "TestUser3",
            "email": "testuser3@example.com",
            "password1": "testpassword3",
            "password2": "testpassword3",
        }
        #### register
        response = api_client.post(
            registration_url,
            data=new_user_data,
            format='json',
            HTTP_ORIGIN=frontend_url,
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert len(mailoutbox) == 1
        verification_email = mailoutbox[0]
        assert verification_email.to == [new_user_data['email']]
        assert "confirm" in verification_email.subject.lower()
        csrf_token = response.cookies.get('csrftoken')
        assert csrf_token is not None, "CSRF token should be set in registration response"
        
        resend_response = api_client.post(
            resend_email_url,
            data={'email': new_user_data['email']},
            format='json',
            HTTP_ORIGIN=frontend_url,
            HTTP_X_CSRFTOKEN=csrf_token.value
        )
        
        assert resend_response.status_code == status.HTTP_200_OK
        assert len(mailoutbox) == 2, f"Expected 2 emails (registration + resend), got {len(mailoutbox)}"
        
        # Check the resend email (should be the second one)
        resend_email = mailoutbox[1]
        assert resend_email.to == [new_user_data['email']]
        assert "confirm" in resend_email.subject.lower()

        key = key_extractor(resend_email.body)
        verify_response = api_client.post(
            verify_email_url,
            data={'key': key},
            format='json',
            HTTP_ORIGIN=frontend_url,
            HTTP_X_CSRFTOKEN=csrf_token.value
        )
        assert verify_response.status_code == status.HTTP_200_OK
        email_address = EmailAddress.objects.get(email=new_user_data['email'])
        assert email_address.verified

        verify_auth_data = assert_browser_auth_response(verify_response)
        verify_csrf_token = verify_auth_data['csrf_token']

        ################################

        # Step 7: Test password reset flow
        reset_password_response = api_client.post(
            password_reset_url,
            data={'email': new_user_data['email']},
            format='json',
            HTTP_ORIGIN=frontend_url,
            HTTP_X_CSRFTOKEN=verify_csrf_token
        )
        assert reset_password_response.status_code == status.HTTP_200_OK

        reset_password_email = mailoutbox[2]
        keys = key_extractor(reset_password_email.body)

        reset_password_confirm_response = api_client.post(
            password_reset_confirm_url,
            data={
                'uid': keys['uid'], 
                'token': keys['token'], 
                'new_password1': 'newpassword3', 
                'new_password2': 'newpassword3'
            },
            format='json',
            HTTP_ORIGIN=frontend_url,
            # HTTP_X_CSRFTOKEN=verify_csrf_token
        )
        assert reset_password_confirm_response.status_code == status.HTTP_200_OK
        verify_reset_password_response = assert_browser_auth_response(reset_password_confirm_response)