import pytest
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.middleware.csrf import get_token

from users.api.v1.tests.conftest import browser_output, app_output, get_login_response
from django.conf import settings

pytestmark = pytest.mark.django_db 

refresh_cookie_name = settings.REST_AUTH.get('JWT_AUTH_REFRESH_COOKIE', 'jwt-refresh-token')
access_cookie_name = settings.REST_AUTH.get('JWT_AUTH_COOKIE', 'jwt-auth')

class TestEndpoints:

    ####### reigster #######

    def test_registration_endpoint_browser(self, api_client, register_data, registration_url):
        response = api_client.post(registration_url, data=register_data, format='json')
        browser_output(response, status.HTTP_201_CREATED)


    def test_registration_endpoint_app(self, api_client, register_data, registration_url):
        response = api_client.post(registration_url, data=register_data, format='json', headers={'X-Client': 'app'})
        app_output(response, status.HTTP_201_CREATED)


    ####### login #######

    def test_login_endpoint_browser(self, make_user, api_client, login_url):
        user, password = make_user

        login_data = {
            'username': user.username,
            'password': password,
        }

        response = api_client.post(
            login_url, 
            data=login_data, 
            format='json', 
            # headers={'X-Client': 'browser'}
        )
     

        browser_output(response, status.HTTP_200_OK)

    def test_login_endpoint_app(self, make_user, api_client, login_url):
        user, password = make_user

        login_data = {
            'username': user.username,
            'password': password,
        }

        print(f"\nCookies BEFORE request: {api_client.cookies}")

        response = api_client.post(
            login_url, 
            data=login_data, 
            format='json', 
            headers={'X-Client': 'app'}
        )

        app_output(response, status.HTTP_200_OK)

    ####### refresh #######

    def test_refresh_endpoint_browser_with_csrf(self, make_user, api_client, refresh_url, login_url, registration_url, register_data):
        user, password = make_user
        login_response = get_login_response(api_client, login_url, user.username, password, client='browser')

        csrf_cookie = login_response.cookies.get('csrftoken_cookie')
        csrf_token = csrf_cookie.value if csrf_cookie else None

        assert csrf_token is not None, "CSRF token should be available from login"
 
        refresh_response = api_client.post(
            refresh_url, 
            data={}, 
            format='json', 
            headers={
                'X-CSRFToken': csrf_token, 
                'X-Client': 'browser'
            }
        )

        browser_output(refresh_response, status.HTTP_200_OK)

    def test_refresh_endpoint_browser_without_csrf(self, make_user, api_client, refresh_url, login_url):
        """Test that browser refresh fails without CSRF token."""
        user, password = make_user
        get_login_response(api_client, login_url, user.username, password, client='browser')

        refresh_response = api_client.post(
            refresh_url, 
            data={}, 
            format='json', 
            headers={'X-Client': 'browser'}
        )
        assert refresh_response.status_code == status.HTTP_403_FORBIDDEN
        assert 'CSRF token missing from header' in str(refresh_response.data['detail'])

    def test_refresh_browser_without_aud(self, make_user, api_client, refresh_url, login_url):
        """Test that browser refresh fails when refresh token has wrong 'aud' claim."""
        user, password = make_user
        login_response = get_login_response(api_client, login_url, user.username, password, client='browser')

        csrf_cookie = login_response.cookies.get('csrftoken_cookie')
        csrf_token = csrf_cookie.value if csrf_cookie else None

        refresh_cookie = login_response.cookies.get(refresh_cookie_name)
        refresh_token_string = refresh_cookie.value if refresh_cookie else None
        assert refresh_token_string is not None, "Refresh token should be available from login"

        refresh_token = RefreshToken(refresh_token_string)
        refresh_token['aud'] = 'app'  

        api_client.cookies[refresh_cookie_name] = str(refresh_token)

        refresh_response = api_client.post(
            refresh_url, 
            data={}, 
            format='json', 
            headers={
                'X-CSRFToken': csrf_token, 
                'X-Client': 'browser'
            }
        )
        assert refresh_response.status_code == status.HTTP_401_UNAUTHORIZED
        assert 'Invalid token audience' in str(refresh_response.data.get('detail', '')) or \
               'Token missing required "aud"' in str(refresh_response.data.get('detail', ''))
     

    def test_refresh_endpoint_app_with_aud(self, make_user, api_client, refresh_url, login_url):
        user, _ = make_user
        refresh_token = RefreshToken.for_user(user)
        refresh_token['aud'] = 'app'
        refresh = str(refresh_token)

        refresh_response = api_client.post(
            refresh_url, 
            data={'refresh': refresh}, 
            format='json', 
            headers={'X-Client': 'app'}
        )
        
        app_output(refresh_response, status.HTTP_200_OK)

    def test_refresh_endpoint_app_without_aud(self, make_user, api_client, refresh_url, login_url):
        user, _ = make_user
        refresh_token = RefreshToken.for_user(user)
        refresh = str(refresh_token)

        refresh_response = api_client.post(
            refresh_url, 
            data={'refresh': refresh}, 
            format='json', 
            headers={'X-Client': 'app'}
        )

        assert refresh_response.status_code == status.HTTP_401_UNAUTHORIZED
        assert 'Token missing required "aud" (audience) claim' in str(refresh_response.data['detail'])

    ####### logout #######

    def test_logout_endpoint_browser(self, make_user, api_client, logout_url, login_url):
        user, password = make_user
        login_response = get_login_response(api_client, login_url, user.username, password, client='browser')

        csrf_cookie = login_response.cookies.get('csrftoken_cookie')
        csrf_token = csrf_cookie.value if csrf_cookie else None
        refresh_token_before = api_client.cookies.get(refresh_cookie_name)

        logout_response = api_client.post(
            logout_url,
            headers={'X-CSRFToken': csrf_token} if csrf_token else {}
        )
        
        assert logout_response.status_code == status.HTTP_200_OK
        assert logout_response.data.get('detail') == 'Successfully logged out.'
        
        # Check that cookies are marked for deletion in response
        assert refresh_cookie_name in logout_response.cookies, "Refresh token cookie should be deleted"
        assert access_cookie_name in logout_response.cookies, "Access token cookie should be deleted"
        
        if refresh_token_before:
            try:
                RefreshToken(refresh_token_before)
                assert False, "Blacklisted refresh token should raise TokenError"
            except TokenError:
                pass 

    def test_logout_endpoint_app(self, make_user, api_client, logout_url, login_url):
        user, password = make_user
        login_response = get_login_response(api_client, login_url, user.username, password, client='app')
        
        access_token = login_response.data.get('access')
        refresh_token = login_response.data.get('refresh')
        
        logout_response = api_client.post(
            logout_url, 
            data={'refresh': refresh_token}, 
            format='json', 
            headers={
                'Authorization': f'Bearer {access_token}',
                'X-Client': 'app'
            }
        )
        
        assert logout_response.status_code == status.HTTP_200_OK
        assert logout_response.data.get('detail') == 'Successfully logged out.'
        
        try:
            RefreshToken(refresh_token)
            assert False, "Blacklisted refresh token should raise TokenError"
        except TokenError:
            pass  

    ####### email confirm #######

    def test_confirm_email_endpoint_browser(self, api_client, confirm_email_url, register_data, registration_url):
        """Test email confirmation for browser client."""
        # Register user (creates email confirmation)
        registration_response = api_client.post(registration_url, data=register_data, format='json')
        assert registration_response.status_code == status.HTTP_201_CREATED
        
        # Get email confirmation key
        from allauth.account.models import EmailAddress, EmailConfirmationHMAC
        email_address = EmailAddress.objects.get(email=register_data['email'])
        email_confirmation = EmailConfirmationHMAC(email_address)
        key = email_confirmation.key
        
        # Confirm email
        response = api_client.post(
            confirm_email_url,
            data={'key': key},
            format='json',
            headers={'X-Client': 'browser'}
        )
        
        browser_output(response, status.HTTP_200_OK)

    def test_confirm_email_endpoint_app(self, api_client, confirm_email_url, register_data, registration_url):
        """Test email confirmation for app client."""
        # Register user (creates email confirmation)
        registration_response = api_client.post(registration_url, data=register_data, format='json', headers={'X-Client': 'app'})
        assert registration_response.status_code == status.HTTP_201_CREATED
        
        # Get email confirmation key
        from allauth.account.models import EmailAddress, EmailConfirmationHMAC
        email_address = EmailAddress.objects.get(email=register_data['email'])
        email_confirmation = EmailConfirmationHMAC(email_address)
        key = email_confirmation.key
        
        # Confirm email
        response = api_client.post(
            confirm_email_url,
            data={'key': key},
            format='json',
            headers={'X-Client': 'app'}
        )
        
        app_output(response, status.HTTP_200_OK)

    ####### password reset confirm #######

    def test_password_reset_confirm_endpoint_browser(self, make_user, api_client, password_reset_confirm_url):
        """Test password reset confirm for browser client."""
        user, _ = make_user
        
        # Generate password reset token
        from allauth.account.utils import user_pk_to_url_str
        from allauth.account.forms import default_token_generator
        uid = user_pk_to_url_str(user)
        token = default_token_generator.make_token(user)
        
        # Reset password
        response = api_client.post(
            password_reset_confirm_url,
            data={
                'uid': uid,
                'token': token,
                'new_password1': 'NewPassword123!',
                'new_password2': 'NewPassword123!'
            },
            format='json',
            headers={'X-Client': 'browser'}
        )
        
        browser_output(response, status.HTTP_200_OK)

    def test_password_reset_confirm_endpoint_app(self, make_user, api_client, password_reset_confirm_url):
        """Test password reset confirm for app client."""
        user, _ = make_user
        
        # Generate password reset token
        from allauth.account.utils import user_pk_to_url_str
        from allauth.account.forms import default_token_generator
        uid = user_pk_to_url_str(user)
        token = default_token_generator.make_token(user)
        
        # Reset password
        response = api_client.post(
            password_reset_confirm_url,
            data={
                'uid': uid,
                'token': token,
                'new_password1': 'NewPassword123!',
                'new_password2': 'NewPassword123!'
            },
            format='json',
            headers={'X-Client': 'app'}
        )
        
        app_output(response, status.HTTP_200_OK)