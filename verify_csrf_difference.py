#!/usr/bin/env python
"""
Verify the key difference between custom and built-in CSRF protection:
- Built-in enforces CSRF on ALL methods including GET
- Custom only enforces CSRF on unsafe methods (POST, PUT, PATCH, DELETE)
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

User = get_user_model()

def test_get_request_csrf_behavior():
    """
    Test whether GET requests require CSRF tokens.
    This is the KEY DIFFERENCE between the two implementations.
    """
    
    # Create or get test user
    user, created = User.objects.get_or_create(
        username='csrf_test_user',
        defaults={'email': 'csrf_test@test.com'}
    )
    if created:
        user.set_password('testpass123')
        user.save()
    
    # Generate tokens
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)
    
    # Create request factory
    factory = RequestFactory()
    
    print("=" * 80)
    print("CSRF Protection Behavior Comparison: GET Requests")
    print("=" * 80)
    
    # Test 1: Built-in JWTCookieAuthentication with GET request
    print("\n1. Testing Built-in JWTCookieAuthentication on GET request:")
    print("-" * 80)
    
    request_get = factory.get(
        '/api/v1/auth/user/',
        HTTP_ORIGIN='http://localhost:3000'
    )
    request_get.COOKIES = {
        settings.REST_AUTH['JWT_AUTH_COOKIE']: access_token
    }
    # NO CSRF token provided
    
    auth_builtin = JWTCookieAuthentication()
    try:
        result = auth_builtin.authenticate(request_get)
        if result:
            print(f"❌ GET request succeeded WITHOUT CSRF token")
            print(f"   User: {result[0].username}")
            print(f"   This means GET requests DON'T require CSRF with built-in class")
        else:
            print("⚠️  Authentication returned None")
    except PermissionDenied as e:
        print(f"⚠️  CSRF enforced on GET request: {e}")
        print(f"   This means built-in class requires CSRF even for safe GET requests!")
    except Exception as e:
        print(f"❌ Unexpected error: {type(e).__name__}: {e}")
    
    # Test 2: Custom JWTCookieAuthenticationWithCSRF with GET request
    print("\n2. Testing Custom JWTCookieAuthenticationWithCSRF on GET request:")
    print("-" * 80)
    
    request_get2 = factory.get(
        '/api/v1/auth/user/',
        HTTP_ORIGIN='http://localhost:3000'
    )
    request_get2.COOKIES = {
        settings.REST_AUTH['JWT_AUTH_COOKIE']: access_token
    }
    # NO CSRF token provided
    
    auth_custom = JWTCookieAuthenticationWithCSRF()
    try:
        result = auth_custom.authenticate(request_get2)
        if result:
            print(f"✅ GET request succeeded WITHOUT CSRF token")
            print(f"   User: {result[0].username}")
            print(f"   This is CORRECT - GET requests should not require CSRF")
        else:
            print("⚠️  Authentication returned None")
    except PermissionDenied as e:
        print(f"❌ CSRF enforced on GET request: {e}")
        print(f"   This is INCORRECT - GET should be allowed without CSRF")
    except Exception as e:
        print(f"❌ Unexpected error: {type(e).__name__}: {e}")
    
    # Test 3: Custom class with POST request (should enforce CSRF)
    print("\n3. Testing Custom class on POST request without CSRF:")
    print("-" * 80)
    
    request_post = factory.post(
        '/api/v1/auth/logout/',
        HTTP_ORIGIN='http://localhost:3000'
    )
    request_post.COOKIES = {
        settings.REST_AUTH['JWT_AUTH_COOKIE']: access_token
    }
    # NO CSRF token provided
    
    auth_custom2 = JWTCookieAuthenticationWithCSRF()
    try:
        result = auth_custom2.authenticate(request_post)
        if result:
            print(f"❌ POST request succeeded WITHOUT CSRF token")
            print(f"   This is WRONG - unsafe methods should require CSRF")
        else:
            print("⚠️  Authentication returned None")
    except PermissionDenied as e:
        print(f"✅ CSRF correctly enforced on POST request: {e}")
        print(f"   This is CORRECT - POST should require CSRF token")
    except Exception as e:
        print(f"❌ Unexpected error: {type(e).__name__}: {e}")
    
    print("\n" + "=" * 80)
    print("CONCLUSION:")
    print("=" * 80)
    print("If the built-in class rejects GET requests without CSRF,")
    print("then your custom class is BETTER because:")
    print("  ✅ It correctly allows safe GET requests without CSRF")
    print("  ✅ It only requires CSRF for unsafe methods (POST, PUT, PATCH, DELETE)")
    print("  ✅ It follows HTTP semantics and Django best practices")
    print("=" * 80)

if __name__ == '__main__':
    test_get_request_csrf_behavior()

