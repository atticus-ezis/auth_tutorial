# CSRF Double Submit Protection

This implementation provides CSRF protection using the double submit method for browser-based requests.

## How It Works

### 1. Token Generation

When a user logs in via a browser (detected by Origin header), the server:

- Generates a secure CSRF token using `secrets.token_urlsafe(32)`
- Sets the token in a cookie named `csrf-token`
- Returns the token in the response body for the frontend to use

### 2. Token Validation

For subsequent requests from browsers, the server:

- Checks for the presence of both cookie and header tokens
- Validates that the `X-CSRF-Token` header matches the `csrf-token` cookie
- Uses `secrets.compare_digest()` for timing-safe comparison

### 3. Browser Detection

The system detects browser requests by:

1. Checking for explicit `X-Auth-Type` header (`session`, `cookie`, or `browser`)
2. Falling back to checking for `Origin` header presence
3. Validating origin against `CORS_ALLOWED_ORIGINS` if configured

## Frontend Integration

### JavaScript Example

```javascript
// After login, store the CSRF token
const loginResponse = await fetch("/api/v1/auth/login/", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    Origin: "http://localhost:3000",
  },
  credentials: "include", // Important: include cookies
  body: JSON.stringify({
    username: "user",
    password: "pass",
  }),
});

const data = await loginResponse.json();
const csrfToken = data.csrf_token;

// For subsequent requests, include the CSRF token
const protectedResponse = await fetch("/api/v1/auth/user/", {
  method: "GET",
  headers: {
    "X-CSRF-Token": csrfToken,
    Origin: "http://localhost:3000",
  },
  credentials: "include", // Important: include cookies
});
```

### React Example

```jsx
import { useState, useEffect } from "react";

function useCSRF() {
  const [csrfToken, setCsrfToken] = useState(null);

  useEffect(() => {
    // Get CSRF token from login response or dedicated endpoint
    fetch("/api/v1/auth/csrf/", {
      credentials: "include",
    })
      .then((response) => response.json())
      .then((data) => setCsrfToken(data.csrf_token));
  }, []);

  return csrfToken;
}

function ProtectedComponent() {
  const csrfToken = useCSRF();

  const makeRequest = async () => {
    const response = await fetch("/api/v1/auth/user/", {
      headers: {
        "X-CSRF-Token": csrfToken,
        Origin: window.location.origin,
      },
      credentials: "include",
    });
    return response.json();
  };

  // ... rest of component
}
```

## Security Features

### Cookie Configuration

- **Secure**: `True` in production, `False` in development
- **HttpOnly**: `False` (must be accessible to JavaScript for double submit)
- **SameSite**: `Lax` (prevents CSRF while allowing legitimate cross-site requests)
- **Max Age**: 1 hour (3600 seconds)

### Token Security

- **Length**: 32 bytes (256 bits) of entropy
- **Algorithm**: URL-safe base64 encoding
- **Comparison**: Timing-safe using `secrets.compare_digest()`

## Configuration

### Django Settings

```python
# In settings.py
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "https://yourdomain.com"
]

CORS_ALLOW_CREDENTIALS = True

CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "https://yourdomain.com"
]
```

### REST Framework Settings

```python
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        "users.authentication.JWTCookieAuthenticationWithCSRF",  # CSRF-enabled auth
        "rest_framework.authentication.SessionAuthentication",
    ],
}
```

## Testing

Run the test script to verify CSRF protection:

```bash
python test_csrf_protection.py
```

This will:

1. Login and receive a CSRF token
2. Attempt to access a protected endpoint without the token (should fail)
3. Access the protected endpoint with the token (should succeed)

## Mobile/Desktop Apps

Mobile and desktop apps are not affected by CSRF protection:

- They don't send `Origin` headers
- They can use the `X-Auth-Type: jwt` header to explicitly opt out
- They receive JWT tokens in the response body instead of cookies

## Troubleshooting

### Common Issues

1. **"CSRF token validation failed"**

   - Ensure the frontend is sending the `X-CSRF-Token` header
   - Check that cookies are being sent with requests (`credentials: 'include'`)
   - Verify the Origin header is set correctly

2. **Token not being set**

   - Ensure the request is detected as a browser request
   - Check that the Origin header matches `CORS_ALLOWED_ORIGINS`

3. **CORS issues**
   - Make sure `CORS_ALLOW_CREDENTIALS = True`
   - Verify `CORS_ALLOWED_ORIGINS` includes your frontend domain
   - Check that `CSRF_TRUSTED_ORIGINS` is configured
