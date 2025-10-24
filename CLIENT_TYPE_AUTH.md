# Origin-Based Authentication

This project uses a mixin-based approach to handle JWT authentication for different client types (web browsers vs mobile/desktop apps).

## How It Works

The `CookiesOrAuthorizationJWTMixin` checks the `Origin` header in requests and adapts the JWT response format:

### For Web/Browser Clients

**Detection:** Automatically detected via `Origin` header matching `CORS_ALLOWED_ORIGINS`

**Response:**

- JWT tokens are set as HttpOnly cookies (`jwt-auth` and `jwt-refresh-token`)
- Tokens are removed from the response body
- CSRF token is included in the response body
- Frontend needs to include CSRF token in subsequent requests

**Example:**

```bash
curl -X POST http://localhost:8000/api/v1/auth/login/ \
  -H "Content-Type: application/json" \
  -H "Origin: http://localhost:3000" \
  -d '{"username": "user", "password": "password123"}' \
  -c cookies.txt

# Response:
{
  "user": {...},
  "csrf_token": "abc123..."
}
# Cookies: jwt-auth=<token>, jwt-refresh-token=<token>
```

### For Mobile/Desktop Clients

**Detection:** No `Origin` header or Origin doesn't match allowed origins

**Response:**

- JWT tokens are returned in the JSON response body
- No cookies are set
- Client stores tokens and sends via `Authorization: Bearer <token>` header

**Example:**

```bash
curl -X POST http://localhost:8000/api/v1/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username": "user", "password": "password123"}'

# Response:
{
  "access": "eyJ0eXAiOiJKV1QiLCJh...",
  "refresh": "eyJ0eXAiOiJKV1QiLCJh...",
  "user": {...}
}
```

## Endpoints Using This Mixin

All authentication endpoints that return JWT tokens use this mixin:

1. **Login:** `POST /api/v1/auth/login/`
2. **Registration:** `POST /api/v1/auth/registration/`
3. **Token Refresh:** `POST /api/v1/auth/token/refresh/`
4. **Email Verification:** `POST /api/v1/auth/registration/account-confirm-email/`
5. **Password Reset Confirm:** `POST /api/v1/auth/password/reset/confirm/`

## Authentication Classes

Your DRF settings support both authentication methods:

```python
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "dj_rest_auth.jwt_auth.JWTCookieAuthentication",  # For cookie-based auth
        "rest_framework_simplejwt.authentication.JWTAuthentication",  # For header-based auth
        "rest_framework.authentication.SessionAuthentication",
    ],
}
```

## Client Implementation

### Web/Browser Client (React, Vue, etc.)

```javascript
// Login - Origin header is sent automatically by browsers
const response = await fetch("/api/v1/auth/login/", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
  },
  credentials: "include", // Important: include cookies
  body: JSON.stringify({ username, password }),
});

const data = await response.json();
// Store CSRF token for future requests
localStorage.setItem("csrfToken", data.csrf_token);

// Subsequent authenticated requests
await fetch("/api/v1/some-endpoint/", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-CSRFToken": localStorage.getItem("csrfToken"),
  },
  credentials: "include", // Cookies sent automatically
});
```

### Mobile/Desktop Client

```javascript
// Login - No Origin header (or non-matching Origin)
const response = await fetch("/api/v1/auth/login/", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ username, password }),
});

const { access, refresh } = await response.json();
// Store tokens securely (e.g., secure storage, keychain)
await secureStorage.setItem("accessToken", access);
await secureStorage.setItem("refreshToken", refresh);

// Subsequent authenticated requests
await fetch("/api/v1/some-endpoint/", {
  method: "GET",
  headers: {
    Authorization: `Bearer ${await secureStorage.getItem("accessToken")}`,
  },
});
```

## Benefits

1. **Single Codebase:** One set of endpoints handles both web and mobile clients
2. **Security:** Web clients use HttpOnly cookies (protected from XSS)
3. **Automatic Detection:** Uses browser's native Origin header - no manual configuration needed
4. **Flexibility:** Mobile apps can manage tokens as needed
5. **CORS Integration:** Works seamlessly with existing CORS settings
6. **Maintainable:** Mixin can be reused across all auth endpoints

## How Detection Works

The mixin automatically detects client type by checking:

1. If an `Origin` header is present in the request
2. If that Origin matches any URL in `CORS_ALLOWED_ORIGINS` or `FRONTEND_URL`
3. If both conditions are true → Browser client (cookies + CSRF)
4. Otherwise → Mobile/Desktop client (JSON tokens)
