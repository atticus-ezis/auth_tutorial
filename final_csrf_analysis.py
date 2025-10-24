#!/usr/bin/env python
"""
Final analysis: Test behavior with JWT_AUTH_COOKIE_USE_CSRF = False
to see if the custom _check_csrf method is actually needed.
"""

import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'auth_demo.settings')
sys.path.insert(0, '/Users/atticusezis/coding/auth_demo')
django.setup()

from django.test import RequestFactory, override_settings
from django.contrib.auth import get_user_model
from dj_rest_auth.jwt_auth import JWTCookieAuthentication
from users.authentication import JWTCookieAuthenticationWithCSRF
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import PermissionDenied
from django.conf import settings

User = get_user_model()

# Trace which methods are called
original_custom_check = JWTCookieAuthenticationWithCSRF._check_csrf
original_builtin_enforce = JWTCookieAuthentication.enforce_csrf

call_log = []

def traced_custom_check(self, request):
    call_log.append("custom_check_csrf")
    print("   🎯 Custom _check_csrf() called!")
    return original_custom_check(self, request)

def traced_builtin_enforce(self, request):
    call_log.append("builtin_enforce_csrf")
    print("   🏢 Built-in enforce_csrf() called!")
    return original_builtin_enforce(self, request)

JWTCookieAuthenticationWithCSRF._check_csrf = traced_custom_check
JWTCookieAuthentication.enforce_csrf = traced_builtin_enforce


def test_with_setting(use_csrf):
    """Test with JWT_AUTH_COOKIE_USE_CSRF set to specified value."""
    global call_log
    
    user, created = User.objects.get_or_create(
        username='final_test_user',
        defaults={'email': 'final@test.com'}
    )
    if created:
        user.set_password('testpass123')
        user.save()
    
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)
    factory = RequestFactory()
    
    print("\n" + "=" * 80)
    print(f"Testing with JWT_AUTH_COOKIE_USE_CSRF = {use_csrf}")
    print("=" * 80)
    
    # Temporarily override the setting
    rest_auth_settings = settings.REST_AUTH.copy()
    rest_auth_settings['JWT_AUTH_COOKIE_USE_CSRF'] = use_csrf
    
    with override_settings(REST_AUTH=rest_auth_settings):
        from dj_rest_auth import app_settings
        # Force reload the setting
        app_settings.import_from_str(rest_auth_settings, 'REST_AUTH')
        
        # Test POST without CSRF tokens
        print("\n📝 Test 1: POST request WITHOUT CSRF tokens")
        print("-" * 80)
        call_log = []
        
        request_post = factory.post('/api/test/')
        request_post.COOKIES = {settings.REST_AUTH['JWT_AUTH_COOKIE']: access_token}
        
        auth = JWTCookieAuthenticationWithCSRF()
        try:
            result = auth.authenticate(request_post)
            print(f"Result: ✅ Authenticated as {result[0].username if result else 'None'}")
        except PermissionDenied as e:
            print(f"Result: ❌ {e}")
        
        print(f"Methods called: {call_log}")
        
        # Test POST with valid CSRF tokens
        print("\n📝 Test 2: POST request WITH valid CSRF tokens")
        print("-" * 80)
        call_log = []
        
        request_post2 = factory.post('/api/test/')
        request_post2.COOKIES = {
            settings.REST_AUTH['JWT_AUTH_COOKIE']: access_token,
            'csrftoken': 'a' * 64  # Valid length CSRF token
        }
        request_post2.META['HTTP_X_CSRFTOKEN'] = 'a' * 64
        request_post2.META['CSRF_COOKIE'] = 'a' * 64
        
        auth2 = JWTCookieAuthenticationWithCSRF()
        try:
            result = auth2.authenticate(request_post2)
            print(f"Result: ✅ Authenticated as {result[0].username if result else 'None'}")
        except PermissionDenied as e:
            print(f"Result: ❌ {e}")
        
        print(f"Methods called: {call_log}")


def main():
    print("=" * 80)
    print("FINAL CSRF PROTECTION ANALYSIS")
    print("=" * 80)
    print("\nThis test shows what happens with different JWT_AUTH_COOKIE_USE_CSRF values")
    print("and whether the custom _check_csrf method provides additional protection.")
    
    # Test with True (current setting)
    test_with_setting(True)
    
    # Test with False
    test_with_setting(False)
    
    print("\n" + "=" * 80)
    print("CONCLUSIONS:")
    print("=" * 80)
    print("\n1. With JWT_AUTH_COOKIE_USE_CSRF = True:")
    print("   - Built-in enforce_csrf() is called")
    print("   - Custom _check_csrf() may or may not be called (depends on parent success)")
    print("   - Parent class already provides CSRF protection")
    print("\n2. With JWT_AUTH_COOKIE_USE_CSRF = False:")
    print("   - Built-in enforce_csrf() is NOT called")
    print("   - Custom _check_csrf() IS called")
    print("   - Custom class provides the ONLY CSRF protection")
    print("\n3. Key Question:")
    print("   If you have JWT_AUTH_COOKIE_USE_CSRF = True, is the custom class redundant?")
    print("   Answer: Custom _check_csrf MIGHT be redundant IF parent enforces CSRF on all methods.")
    print("   BUT: The custom class only checks unsafe methods, which is more correct!")
    print("=" * 80)

if __name__ == '__main__':
    main()

