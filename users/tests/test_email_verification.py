"""
Pytest tests for email verification flow
"""
import pytest
from django.contrib.auth import get_user_model
from django.core import mail
from django.test import override_settings
from rest_framework import status
from allauth.account.models import EmailAddress
import json

User = get_user_model()

pytestmark = pytest.mark.django_db


class TestEmailVerification:
    """Test suite for CustomVerifyEmailView and email verification flow"""

    def test_email_sent_on_send_confirmation(
        self, api_client, registration_url, user_data, clear_mailbox
    ):
        """Test that verification email is sent when send_confirmation is called"""
        # Register user (with optional email verification, this doesn't send email automatically)
        response = api_client.post(
            registration_url,
            data=json.dumps(user_data),
            content_type='application/json'
        )
        
        assert response.status_code == status.HTTP_201_CREATED
        
        # Clear the mailbox (in case registration sent an email)
        mail.outbox = []
        
        # Manually send verification email
        user = User.objects.get(username=user_data['username'])
        email_address = EmailAddress.objects.get(user=user, email=user_data['email'])
        email_address.send_confirmation()
        
        # Check that exactly one email was sent
        assert len(mail.outbox) == 1, "Verification email should be sent when send_confirmation is called"
        
        verification_email = mail.outbox[0]
        
        # Check email properties
        assert user_data['email'] in verification_email.to
        assert 'confirm' in verification_email.subject.lower()
        assert len(verification_email.body) > 0
    
    def test_email_contains_valid_verification_key(
        self, api_client, registration_url, user_data, clear_mailbox, key_extractor
    ):
        """Test that the verification email contains a valid key"""
        # Register user
        response = api_client.post(
            registration_url,
            data=json.dumps(user_data),
            content_type='application/json'
        )
        
        assert response.status_code == status.HTTP_201_CREATED
        
        # Clear mailbox after registration
        mail.outbox = []
        
        # Manually send verification email
        user = User.objects.get(username=user_data['username'])
        email_address = EmailAddress.objects.get(user=user, email=user_data['email'])
        email_address.send_confirmation()
        
        assert len(mail.outbox) == 1
        
        verification_email = mail.outbox[0]
        email_body = verification_email.body
        
        # Extract the verification key from email
        key = key_extractor(email_body)
        
        assert key is not None, "Email should contain a verification key"
        assert len(key) > 10, "Key should be sufficiently long"

    def test_verify_email_with_valid_key_returns_tokens(
        self, api_client, registration_url, verify_email_url, user_data, 
        clear_mailbox, key_extractor
    ):
        """
        Test that verifying email with a valid key returns JWT tokens
        and sets authentication cookies
        """
        # Step 1: Register user
        registration_response = api_client.post(
            registration_url,
            data=json.dumps(user_data),
            content_type='application/json'
        )
        
        assert registration_response.status_code == status.HTTP_201_CREATED
        
        # Manually send verification email
        user = User.objects.get(username=user_data['username'])
        email_address = EmailAddress.objects.get(user=user, email=user_data['email'])
        email_address.send_confirmation()
        
        assert len(mail.outbox) == 1
        
        # Step 2: Extract verification key from email
        verification_email = mail.outbox[0]
        email_body = verification_email.body
        key = key_extractor(email_body)
        
        assert key is not None, "Should be able to extract key from email"
        
        # Step 3: Verify email with the key
        verify_response = api_client.post(
            verify_email_url,
            data=json.dumps({'key': key}),
            content_type='application/json'
        )
        
        # Step 4: Verify response is successful
        assert verify_response.status_code == status.HTTP_200_OK
        
        response_data = verify_response.json()
        
        # Check that response contains success message
        assert 'detail' in response_data
        assert 'confirmed' in response_data['detail'].lower()
        
        # Check that JWT tokens are in response
        assert 'access' in response_data, "Access token should be in response"
        assert 'refresh' in response_data, "Refresh token should be in response"
        
        # Verify tokens are not empty
        assert response_data['access']
        assert response_data['refresh']
        
        # Step 5: Verify cookies are set
        assert 'jwt-auth' in verify_response.cookies, "JWT auth cookie should be set"
        assert 'jwt-refresh-token' in verify_response.cookies, "JWT refresh cookie should be set"
        
        # Verify cookie properties
        jwt_cookie = verify_response.cookies['jwt-auth']
        refresh_cookie = verify_response.cookies['jwt-refresh-token']
        
        assert jwt_cookie['httponly'], "JWT cookie should be httponly"
        assert refresh_cookie['httponly'], "Refresh cookie should be httponly"

    def test_verify_email_with_invalid_key(
        self, api_client, verify_email_url
    ):
        """Test that verifying email with invalid key returns error"""
        verify_response = api_client.post(
            verify_email_url,
            data=json.dumps({'key': 'invalid-key-12345'}),
            content_type='application/json'
        )
        
        # Should return an error
        assert verify_response.status_code == status.HTTP_400_BAD_REQUEST
        response_data = verify_response.json()
        assert 'key' in response_data

    def test_verify_email_without_key(
        self, api_client, verify_email_url
    ):
        """Test that verifying email without key returns error"""
        verify_response = api_client.post(
            verify_email_url,
            data=json.dumps({}),
            content_type='application/json'
        )
        
        # Should return an error
        assert verify_response.status_code == status.HTTP_400_BAD_REQUEST
        response_data = verify_response.json()
        assert 'key' in response_data

    def test_user_can_access_protected_endpoint_after_verification(
        self, api_client, registration_url, verify_email_url, user_details_url,
        user_data, clear_mailbox, key_extractor
    ):
        """Test that user can access protected endpoints after email verification"""
        # Step 1: Register and send verification email
        registration_response = api_client.post(
            registration_url,
            data=json.dumps(user_data),
            content_type='application/json'
        )
        
        assert registration_response.status_code == status.HTTP_201_CREATED
        
        # Manually send verification email
        user = User.objects.get(username=user_data['username'])
        email_address = EmailAddress.objects.get(user=user, email=user_data['email'])
        email_address.send_confirmation()
        
        # Extract key and verify email
        verification_email = mail.outbox[0]
        key = key_extractor(verification_email.body)
        
        verify_response = api_client.post(
            verify_email_url,
            data=json.dumps({'key': key}),
            content_type='application/json'
        )
        
        assert verify_response.status_code == status.HTTP_200_OK
        response_data = verify_response.json()
        access_token = response_data.get('access')
        
        # Step 2: Try to access user details endpoint with the access token
        user_response = api_client.get(
            user_details_url,
            HTTP_AUTHORIZATION=f'Bearer {access_token}'
        )
        
        assert user_response.status_code == status.HTTP_200_OK
        user_response_data = user_response.json()
        assert user_response_data['username'] == user_data['username']
        assert user_response_data['email'] == user_data['email']

    def test_resend_verification_email(
        self, api_client, registration_url, resend_email_url, verify_email_url,
        user_data, clear_mailbox, key_extractor
    ):
        """Test that verification email can be resent"""
        # Step 1: Register user
        registration_response = api_client.post(
            registration_url,
            data=json.dumps(user_data),
            content_type='application/json'
        )
        
        assert registration_response.status_code == status.HTTP_201_CREATED
        
        # Step 2: Request to resend verification email
        resend_response = api_client.post(
            resend_email_url,
            data=json.dumps({'email': user_data['email']}),
            content_type='application/json'
        )
        
        # Check response
        assert resend_response.status_code == status.HTTP_200_OK
        
        # Check that email was sent
        assert len(mail.outbox) >= 1, "Verification email should be resent"
        
        resent_email = mail.outbox[-1]  # Get the last email
        
        # Check email properties
        assert user_data['email'] in resent_email.to
        
        # Extract and verify the new key works
        new_key = key_extractor(resent_email.body)
        assert new_key is not None, "Resent email should contain a key"
        
        # Verify the new key works
        verify_response = api_client.post(
            verify_email_url,
            data=json.dumps({'key': new_key}),
            content_type='application/json'
        )
        
        assert verify_response.status_code == status.HTTP_200_OK

    def test_email_verification_user_status(
        self, api_client, registration_url, verify_email_url, user_data, 
        clear_mailbox, key_extractor
    ):
        """Test that user's email is marked as verified after confirmation"""
        # Register user
        api_client.post(
            registration_url,
            data=json.dumps(user_data),
            content_type='application/json'
        )
        
        # Get user from database
        user = User.objects.get(username=user_data['username'])
        
        # Check email is not verified initially
        email_address = EmailAddress.objects.get(user=user, email=user_data['email'])
        
        # Manually unverify it for testing
        email_address.verified = False
        email_address.save()
        
        assert not email_address.verified, "Email should not be verified initially"
        
        # Send verification email
        email_address.send_confirmation()
        
        # Extract key and verify email
        verification_email = mail.outbox[0]
        key = key_extractor(verification_email.body)
        
        api_client.post(
            verify_email_url,
            data=json.dumps({'key': key}),
            content_type='application/json'
        )
        
        # Refresh email address from database
        email_address.refresh_from_db()
        
        assert email_address.verified, "Email should be verified after confirmation"

