#!/usr/bin/env python
"""
Detailed trace to understand which CSRF check is actually being called.
"""

import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'auth_demo.settings')
sys.path.insert(0, '/Users/atticusezis/coding/auth_demo')
django.setup()

from django.test import RequestFactory
from django.contrib.auth import get_user_model
from dj_rest_auth.jwt_auth import JWTCookieAuthentication
from users.authentication import JWTCookieAuthenticationWithCSRF
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import PermissionDenied
from django.conf import settings
import traceback

User = get_user_model()

# Patch the custom class to trace when _check_csrf is called
original_check_csrf = JWTCookieAuthenticationWithCSRF._check_csrf

def traced_check_csrf(self, request):
    print("   🔍 Custom _check_csrf() method called!")
    return original_check_csrf(self, request)

JWTCookieAuthenticationWithCSRF._check_csrf = traced_check_csrf

# Patch the built-in class to trace when enforce_csrf is called
original_enforce_csrf = JWTCookieAuthentication.enforce_csrf

def traced_enforce_csrf(self, request):
    print("   🔍 Built-in enforce_csrf() method called!")
    return original_enforce_csrf(self, request)

JWTCookieAuthentication.enforce_csrf = traced_enforce_csrf


def test_which_csrf_check():
    """Test to see which CSRF method is actually being called."""
    
    user, created = User.objects.get_or_create(
        username='trace_test_user',
        defaults={'email': 'trace@test.com'}
    )
    if created:
        user.set_password('testpass123')
        user.save()
    
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)
    
    factory = RequestFactory()
    
    print("=" * 80)
    print("Tracing Which CSRF Check Method is Called")
    print("=" * 80)
    print(f"\nCurrent setting: JWT_AUTH_COOKIE_USE_CSRF = {settings.REST_AUTH.get('JWT_AUTH_COOKIE_USE_CSRF')}")
    
    # Test 1: Custom class with POST (no CSRF token)
    print("\n" + "=" * 80)
    print("TEST 1: Custom JWTCookieAuthenticationWithCSRF - POST without CSRF")
    print("=" * 80)
    
    request_post = factory.post('/api/test/')
    request_post.COOKIES = {
        settings.REST_AUTH['JWT_AUTH_COOKIE']: access_token
    }
    
    auth_custom = JWTCookieAuthenticationWithCSRF()
    try:
        print("Calling authenticate()...")
        result = auth_custom.authenticate(request_post)
        print(f"✅ Authentication succeeded: {result[0].username if result else 'None'}")
    except PermissionDenied as e:
        print(f"❌ CSRF check failed: {e}")
    except Exception as e:
        print(f"❌ Error: {type(e).__name__}: {e}")
    
    # Test 2: Custom class with POST (with CSRF token in cookie but not header)
    print("\n" + "=" * 80)
    print("TEST 2: Custom class - POST with CSRF cookie but no header")
    print("=" * 80)
    
    request_post2 = factory.post('/api/test/')
    request_post2.COOKIES = {
        settings.REST_AUTH['JWT_AUTH_COOKIE']: access_token,
        'csrftoken': 'test-csrf-token-value'
    }
    
    auth_custom2 = JWTCookieAuthenticationWithCSRF()
    try:
        print("Calling authenticate()...")
        result = auth_custom2.authenticate(request_post2)
        print(f"✅ Authentication succeeded: {result[0].username if result else 'None'}")
    except PermissionDenied as e:
        print(f"❌ CSRF check failed: {e}")
        print("\nFull traceback:")
        traceback.print_exc()
    
    # Test 3: Custom class with POST (with matching CSRF tokens)
    print("\n" + "=" * 80)
    print("TEST 3: Custom class - POST with matching CSRF tokens")
    print("=" * 80)
    
    request_post3 = factory.post('/api/test/')
    request_post3.COOKIES = {
        settings.REST_AUTH['JWT_AUTH_COOKIE']: access_token,
        'csrftoken': 'test-csrf-token-value'
    }
    request_post3.META['HTTP_X_CSRFTOKEN'] = 'test-csrf-token-value'
    
    auth_custom3 = JWTCookieAuthenticationWithCSRF()
    try:
        print("Calling authenticate()...")
        result = auth_custom3.authenticate(request_post3)
        print(f"✅ Authentication succeeded: {result[0].username if result else 'None'}")
    except PermissionDenied as e:
        print(f"❌ CSRF check failed: {e}")
    
    # Test 4: GET request - should not trigger custom _check_csrf
    print("\n" + "=" * 80)
    print("TEST 4: Custom class - GET request (should skip custom CSRF check)")
    print("=" * 80)
    
    request_get = factory.get('/api/test/')
    request_get.COOKIES = {
        settings.REST_AUTH['JWT_AUTH_COOKIE']: access_token
    }
    
    auth_custom4 = JWTCookieAuthenticationWithCSRF()
    try:
        print("Calling authenticate()...")
        result = auth_custom4.authenticate(request_get)
        print(f"✅ Authentication succeeded: {result[0].username if result else 'None'}")
    except PermissionDenied as e:
        print(f"❌ CSRF check failed: {e}")
    
    print("\n" + "=" * 80)
    print("ANALYSIS:")
    print("=" * 80)
    print("- If you see '🔍 Built-in enforce_csrf() method called!'")
    print("  then the parent class is doing CSRF validation")
    print("- If you see '🔍 Custom _check_csrf() method called!'")
    print("  then your custom method is doing additional CSRF validation")
    print("- Both might be called, indicating double CSRF checking!")
    print("=" * 80)

if __name__ == '__main__':
    test_which_csrf_check()

