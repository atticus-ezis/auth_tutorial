"""
Pytest tests for password reset flow
"""
import pytest
from django.contrib.auth import get_user_model
from django.core import mail
from rest_framework import status
from allauth.account.utils import user_pk_to_url_str
from allauth.account.forms import default_token_generator
import json

User = get_user_model()

pytestmark = pytest.mark.django_db


class TestPasswordReset:
    """Test suite for CustomPasswordResetConfirmView"""

    @pytest.fixture
    def test_user(self, user_data):
        """Create a test user"""
        return User.objects.create_user(
            username=user_data['username'],
            email=user_data['email'],
            password='OldPassword123!'
        )

    @pytest.fixture
    def new_password(self):
        """New password for reset"""
        return 'NewPassword456!'

    def test_password_reset_flow_with_auto_login(
        self, api_client, password_reset_url, password_reset_confirm_url,
        test_user, new_password, clear_mailbox
    ):
        """
        Test complete password reset flow:
        1. Request password reset
        2. Confirm password reset
        3. Verify tokens are returned
        4. Verify cookies are set
        """
        # Step 1: Request password reset
        reset_response = api_client.post(
            password_reset_url,
            data={'email': test_user.email},
            format='json'
        )
        
        assert reset_response.status_code == status.HTTP_200_OK
        assert len(mail.outbox) == 1
        
        # Extract uid and token (as they would be in the email)
        uid = user_pk_to_url_str(test_user)
        token = default_token_generator.make_token(test_user)
        
        # Step 2: Confirm password reset with new password
        confirm_data = {
            'uid': uid,
            'token': token,
            'new_password1': new_password,
            'new_password2': new_password,
        }
        
        confirm_response = api_client.post(
            password_reset_confirm_url,
            data=json.dumps(confirm_data),
            content_type='application/json'
        )
        
        # Step 3: Verify response
        assert confirm_response.status_code == status.HTTP_200_OK
        response_data = confirm_response.json()
        
        # Check that response contains success message
        assert 'detail' in response_data
        
        # Check that JWT tokens are in response
        assert 'access' in response_data, "Access token should be in response"
        assert 'refresh' in response_data, "Refresh token should be in response"
        
        # Verify tokens are not empty
        assert response_data['access']
        assert response_data['refresh']
        
        # Step 4: Verify cookies are set
        assert 'jwt-auth' in confirm_response.cookies, "JWT auth cookie should be set"
        assert 'jwt-refresh-token' in confirm_response.cookies, "JWT refresh cookie should be set"
        
        # Verify cookie properties
        jwt_cookie = confirm_response.cookies['jwt-auth']
        refresh_cookie = confirm_response.cookies['jwt-refresh-token']
        
        assert jwt_cookie['httponly'], "JWT cookie should be httponly"
        assert refresh_cookie['httponly'], "Refresh cookie should be httponly"
        
        # Step 5: Verify password was actually changed
        test_user.refresh_from_db()
        assert test_user.check_password(new_password), \
            "Password should be updated to new password"
        assert not test_user.check_password('OldPassword123!'), \
            "Old password should no longer work"

    def test_password_reset_with_invalid_uid(
        self, api_client, password_reset_confirm_url, new_password
    ):
        """Test password reset with invalid uid returns error"""
        confirm_data = {
            'uid': 'invalid-uid',
            'token': 'invalid-token',
            'new_password1': new_password,
            'new_password2': new_password,
        }
        
        confirm_response = api_client.post(
            password_reset_confirm_url,
            data=json.dumps(confirm_data),
            content_type='application/json'
        )
        
        # Should return an error
        assert confirm_response.status_code == status.HTTP_400_BAD_REQUEST

    def test_password_reset_with_mismatched_passwords(
        self, api_client, password_reset_confirm_url, test_user
    ):
        """Test password reset with mismatched passwords"""
        uid = user_pk_to_url_str(test_user)
        token = default_token_generator.make_token(test_user)
        
        confirm_data = {
            'uid': uid,
            'token': token,
            'new_password1': 'NewPassword123!',
            'new_password2': 'DifferentPassword456!',
        }
        
        confirm_response = api_client.post(
            password_reset_confirm_url,
            data=json.dumps(confirm_data),
            content_type='application/json'
        )
        
        # Should return an error
        assert confirm_response.status_code == status.HTTP_400_BAD_REQUEST

    def test_user_can_access_protected_endpoint_after_reset(
        self, api_client, password_reset_url, password_reset_confirm_url,
        user_details_url, test_user, new_password, clear_mailbox
    ):
        """Test that user can access protected endpoints with the returned JWT tokens"""
        # Request password reset
        api_client.post(
            password_reset_url,
            data={'email': test_user.email},
            format='json'
        )
        
        # Confirm password reset
        uid = user_pk_to_url_str(test_user)
        token = default_token_generator.make_token(test_user)
        
        confirm_data = {
            'uid': uid,
            'token': token,
            'new_password1': new_password,
            'new_password2': new_password,
        }
        
        confirm_response = api_client.post(
            password_reset_confirm_url,
            data=json.dumps(confirm_data),
            content_type='application/json'
        )
        
        response_data = confirm_response.json()
        access_token = response_data.get('access')
        
        # Try to access user details endpoint with the access token
        user_response = api_client.get(
            user_details_url,
            HTTP_AUTHORIZATION=f'Bearer {access_token}'
        )
        
        assert user_response.status_code == status.HTTP_200_OK
        user_data = user_response.json()
        assert user_data['username'] == test_user.username
        assert user_data['email'] == test_user.email

    def test_custom_reset( self, api_client, password_reset_url, password_reset_confirm_url,
        user_details_url, test_user, new_password, clear_mailbox):
        uid = user_pk_to_url_str(test_user)
        token = default_token_generator.make_token(test_user)
        
        confirm_data = {
            'uid': uid,
            'token': token,
            'new_password1': new_password,
            'new_password2': new_password,
        }

        confirm_response = api_client.post(
            password_reset_confirm_url,
            data=json.dumps(confirm_data),
            content_type='application/json'
        )

        assert confirm_response.status_code == status.HTTP_200_OK
        response_data = confirm_response.json()
        assert response_data['access']
        assert response_data['refresh']

        