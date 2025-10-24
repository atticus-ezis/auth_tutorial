#!/usr/bin/env python3
"""
Test script to demonstrate CSRF double submit protection.

This script shows how the CSRF protection works:
1. Login request returns CSRF token in response and sets it in cookie
2. Subsequent requests must include the CSRF token in X-CSRF-Token header
3. The server validates that cookie and header tokens match
"""

import requests
import json

# Configuration
BASE_URL = "http://localhost:8000"
LOGIN_URL = f"{BASE_URL}/api/v1/auth/login/"
PROTECTED_URL = f"{BASE_URL}/api/v1/auth/user/"

def test_csrf_protection():
    """Test CSRF double submit protection."""
    
    # Create a session to maintain cookies
    session = requests.Session()
    
    print("🔐 Testing CSRF Double Submit Protection")
    print("=" * 50)
    
    # Step 1: Login and get CSRF token
    print("\n1. Logging in to get CSRF token...")
    login_data = {
        "username": "testuser",  # Replace with actual test user
        "password": "testpass"   # Replace with actual test password
    }
    
    # Add Origin header to simulate browser request
    headers = {
        "Origin": "http://localhost:3000",
        "Content-Type": "application/json"
    }
    
    try:
        response = session.post(LOGIN_URL, json=login_data, headers=headers)
        print(f"Login response status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            csrf_token = data.get('csrf_token')
            print(f"✅ CSRF token received: {csrf_token[:20]}...")
            print(f"✅ CSRF cookie set: {'csrf-token' in session.cookies}")
            
            # Step 2: Test protected endpoint without CSRF token (should fail)
            print("\n2. Testing protected endpoint WITHOUT CSRF token (should fail)...")
            response = session.get(PROTECTED_URL, headers={"Origin": "http://localhost:3000"})
            print(f"Response status: {response.status_code}")
            if response.status_code == 401:
                print("✅ Correctly rejected request without CSRF token")
            else:
                print("❌ Request should have been rejected")
            
            # Step 3: Test protected endpoint with CSRF token (should succeed)
            print("\n3. Testing protected endpoint WITH CSRF token (should succeed)...")
            headers_with_csrf = {
                "Origin": "http://localhost:3000",
                "X-CSRF-Token": csrf_token
            }
            response = session.get(PROTECTED_URL, headers=headers_with_csrf)
            print(f"Response status: {response.status_code}")
            if response.status_code == 200:
                print("✅ Request accepted with valid CSRF token")
                user_data = response.json()
                print(f"✅ User data retrieved: {user_data.get('username', 'Unknown')}")
            else:
                print("❌ Request should have been accepted")
                print(f"Error: {response.text}")
                
        else:
            print(f"❌ Login failed: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to server. Make sure Django server is running on localhost:8000")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    test_csrf_protection()
