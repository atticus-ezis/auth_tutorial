#!/usr/bin/env python
"""
Debug what the test client is actually sending.
"""

import os
import sys
import django
import pytest

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'auth_demo.settings')
sys.path.insert(0, '/Users/atticusezis/coding/auth_demo')
django.setup()

from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from rest_framework import status
from django.conf import settings

User = get_user_model()


def test_what_client_sends():
    """Check what the APIClient actually sends in requests."""
    
    # Setup
    api_client = APIClient()
    frontend_url = 'http://localhost:3000'
    registration_url = '/api/v1/auth/registration/'
    logout_url = '/api/v1/auth/logout/'
    
    user_data = {
        'username': 'debuguser',
        'email': 'debug@example.com',
        'password1': 'TestPassword123!',
        'password2': 'TestPassword123!'
    }
    
    # Delete user if exists
    User.objects.filter(username='debuguser').delete()
    
    print("=" * 80)
    print("Testing APIClient Behavior")
    print("=" * 80)
    
    # Step 1: Register
    print("\n1. Registration Request:")
    print("-" * 80)
    response = api_client.post(
        registration_url,
        data=user_data,
        format='json',
        HTTP_ORIGIN=frontend_url,
    )
    print(f"Status: {response.status_code}")
    print(f"Cookies set: {list(response.cookies.keys())}")
    
    # Check what cookies the client now has
    print(f"\nAPIClient cookies after registration:")
    for key, value in api_client.cookies.items():
        print(f"  {key}: {str(value)[:50]}...")
    
    csrf_token = response.cookies.get('csrftoken', {}).value if 'csrftoken' in response.cookies else None
    print(f"\nCSRF Token from response: {csrf_token}")
    
    # Step 2: Logout WITHOUT CSRF token
    print("\n2. Logout Request (WITHOUT CSRF token):")
    print("-" * 80)
    
    # Capture the actual request that gets sent
    from unittest.mock import patch
    
    with patch('rest_framework.views.APIView.initial') as mock_initial:
        def check_request(self, request, *args, **kwargs):
            print(f"Request method: {request.method}")
            print(f"Request path: {request.path}")
            print(f"Request cookies: {dict(request.COOKIES)}")
            print(f"Request META HTTP_AUTHORIZATION: {request.META.get('HTTP_AUTHORIZATION', 'NOT SET')}")
            print(f"Request META HTTP_X_CSRFTOKEN: {request.META.get('HTTP_X_CSRFTOKEN', 'NOT SET')}")
            print(f"Request META HTTP_ORIGIN: {request.META.get('HTTP_ORIGIN', 'NOT SET')}")
            print(f"Request user (before auth): {request.user}")
            # Call original
            return mock_initial.return_value
        
        mock_initial.side_effect = check_request
        
        response_no_csrf = api_client.post(
            logout_url,
            data={},
            format='json',
            HTTP_ORIGIN=frontend_url
        )
        
        print(f"\nResponse status: {response_no_csrf.status_code}")
        print(f"Response body: {response_no_csrf.json() if response_no_csrf.status_code != 500 else 'ERROR'}")
    
    print("\n" + "=" * 80)
    print("ANALYSIS:")
    print("=" * 80)
    print("Check if HTTP_AUTHORIZATION header is being set automatically.")
    print("If it is, then JWTAuthentication will handle it WITHOUT CSRF checks!")
    print("=" * 80)

if __name__ == '__main__':
    test_what_client_sends()

