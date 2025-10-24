#!/usr/bin/env python
"""
Debug which authentication class is actually being used for logout.
"""

import os
import sys
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'auth_demo.settings')
sys.path.insert(0, '/Users/atticusezis/coding/auth_demo')
django.setup()

from django.test import RequestFactory
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.authentication import JWTAuthentication
from dj_rest_auth.jwt_auth import JWTCookieAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings

User = get_user_model()

# Patch to trace which class authenticates
original_jwt_auth = JWTAuthentication.authenticate
original_cookie_auth = JWTCookieAuthentication.authenticate

def traced_jwt_auth(self, request):
    result = original_jwt_auth(self, request)
    if result:
        print(f"✅ JWTAuthentication.authenticate() returned: {result[0].username}")
    else:
        print(f"⏭️  JWTAuthentication.authenticate() returned: None (skipped)")
    return result

def traced_cookie_auth(self, request):
    print(f"🔍 JWTCookieAuthentication.authenticate() called")
    result = original_cookie_auth(self, request)
    if result:
        print(f"✅ JWTCookieAuthentication.authenticate() returned: {result[0].username}")
    else:
        print(f"⏭️  JWTCookieAuthentication.authenticate() returned: None")
    return result

JWTAuthentication.authenticate = traced_jwt_auth
JWTCookieAuthentication.authenticate = traced_cookie_auth


def test_logout_authentication():
    """Simulate a logout request to see which auth class handles it."""
    
    user, created = User.objects.get_or_create(
        username='debug_user',
        defaults={'email': 'debug@test.com'}
    )
    if created:
        user.set_password('testpass123')
        user.save()
    
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)
    
    factory = RequestFactory()
    
    print("=" * 80)
    print("Testing Authentication Order for Logout")
    print("=" * 80)
    
    print(f"\nAuthentication classes order:")
    for i, auth_class in enumerate(settings.REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES'], 1):
        print(f"  {i}. {auth_class}")
    
    # Simulate logout request with JWT in cookie (like the test does)
    print("\n" + "-" * 80)
    print("Test: POST /logout with JWT in COOKIE (no Authorization header)")
    print("-" * 80)
    
    request = factory.post('/api/v1/auth/logout/')
    request.COOKIES = {
        settings.REST_AUTH['JWT_AUTH_COOKIE']: access_token
    }
    
    # Try each auth class in order
    for auth_class_path in settings.REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES']:
        parts = auth_class_path.rsplit('.', 1)
        module = __import__(parts[0], fromlist=[parts[1]])
        auth_class = getattr(module, parts[1])
        
        auth_instance = auth_class()
        print(f"\nTrying: {auth_class.__name__}")
        result = auth_instance.authenticate(request)
        
        if result:
            print(f"  ✅ SUCCESS! This class authenticated the user.")
            print(f"  ⚠️  Remaining classes will NOT be tried (DRF stops at first success)")
            break
        else:
            print(f"  ⏭️  SKIPPED. Trying next class...")
    
    print("\n" + "=" * 80)
    print("ANALYSIS:")
    print("=" * 80)
    print("If JWTAuthentication succeeds, it will authenticate WITHOUT CSRF checks,")
    print("and JWTCookieAuthentication will never be called!")
    print("\nSOLUTION: Remove JWTAuthentication from DEFAULT_AUTHENTICATION_CLASSES")
    print("or put JWTCookieAuthentication BEFORE JWTAuthentication.")
    print("=" * 80)

if __name__ == '__main__':
    test_logout_authentication()

