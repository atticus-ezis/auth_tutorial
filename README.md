# Django Hybrid Authentication System

A comprehensive JWT-based authentication system that intelligently adapts between browser and mobile/desktop clients, providing optimal security and user experience for each platform type.

## 🎯 Features

- ✅ **Hybrid Authentication** - Automatically detects browser vs mobile/desktop clients
- ✅ **Browser Security** - HttpOnly cookies with CSRF protection for web clients
- ✅ **Mobile/Desktop Support** - JSON tokens in response body for native apps
- ✅ **Email Verification** - HMAC-based verification with auto-login
- ✅ **Password Reset** - Secure reset flow with automatic authentication
- ✅ **Token Management** - Refresh tokens with blacklisting and rotation
- ✅ **Comprehensive Testing** - Full test suite covering all authentication flows

## 🚀 Quick Start

### Prerequisites

- Python 3.13+
- [uv](https://docs.astral.sh/uv/) (recommended package manager)

### Installation

**Clone the repository:**

```
git clone https://github.com/atticus-ezis/auth_tutorial.git
cd auth_demo
```

**Activate virtual environment:**

```
source .venv/bin/activate
```

**Sync dependencies with uv:**

```
uv sync
```

**Run migrations:**

```
python manage.py migrate
```

**Start server:**

```
python manage.py runserver
```

The server will start at `http://localhost:8000`. Emails will print to the console.

### Running Tests

**Run all tests:**

```
pytest
```

## 🛠️ Tech Stack

- **Django 5.2+** - Web framework
- **Django REST Framework** - API endpoints
- **dj-rest-auth** - Authentication views
- **django-allauth** - Account management
- **djangorestframework-simplejwt** - JWT implementation
- **pytest + pytest-django** - Testing

## 📚 API Endpoints

### Authentication

| Method | Endpoint                      | Auth Required | Description                |
| ------ | ----------------------------- | ------------- | -------------------------- |
| POST   | `/api/v1/auth/registration/`  | ❌            | Register user, returns JWT |
| POST   | `/api/v1/auth/login/`         | ❌            | Login, returns JWT         |
| POST   | `/api/v1/auth/logout/`        | ✅            | Logout, blacklist token    |
| GET    | `/api/v1/auth/user/`          | ✅            | Get user details           |
| POST   | `/api/v1/auth/token/refresh/` | ✅            | Refresh access token       |

### Email Verification

| Method | Endpoint                                           | Auth Required | Description               |
| ------ | -------------------------------------------------- | ------------- | ------------------------- |
| POST   | `/api/v1/auth/registration/account-confirm-email/` | ❌            | Verify email, returns JWT |
| POST   | `/api/v1/auth/registration/resend-email/`          | ❌            | Resend verification email |

### Password Reset

| Method | Endpoint                               | Auth Required | Description                 |
| ------ | -------------------------------------- | ------------- | --------------------------- |
| POST   | `/api/v1/auth/password/reset/`         | ❌            | Request password reset      |
| POST   | `/api/v1/auth/password/reset/confirm/` | ❌            | Confirm reset, returns JWT  |
| POST   | `/api/v1/auth/password/change/`        | ✅            | Change password (logged in) |

## 🔄 Hybrid Authentication Approach

This system intelligently adapts authentication behavior based on the client type:

### Browser Clients (Web Applications)

- **Detection**: Uses `Origin` and `Referer` headers to identify browser requests
- **Security**: HttpOnly cookies with CSRF protection via double-submit pattern
- **Token Delivery**: Tokens stored in secure cookies, CSRF token in response body
- **Response Format**: `authType: 'cookie'` with `csrf_token` field

### Mobile/Desktop Clients (Native Applications)

- **Detection**: Requests without browser-specific headers
- **Security**: Standard JWT authentication via Authorization header
- **Token Delivery**: Tokens returned in JSON response body
- **Response Format**: `authType: 'bearer'` with `access` and `refresh` tokens

### Client Detection Logic

```python
def is_browser_request(request):
    origin = request.headers.get("Origin")
    referer = request.headers.get("Referer")

    # Check if origin/referer matches trusted frontend URLs
    if origin and origin.startswith(settings.FRONTEND_URL):
        return True
    if referer and referer.startswith(settings.FRONTEND_URL):
        return True
    return False
```

### Security Considerations

- **CSRF Protection**: Only enforced for browser clients on unsafe HTTP methods (POST, PUT, PATCH, DELETE)
- **Token Storage**: HttpOnly cookies prevent XSS attacks in browsers
- **Flexibility**: Mobile apps can use standard JWT patterns without CSRF complexity

### Custom Account Adapter

Generates frontend-friendly URLs in emails:

```python
class CustomAccountAdapter(DefaultAccountAdapter):
    def send_mail(self, template_prefix, email, context):
        # Email verification: http://localhost:3000/verify-email/{key}
        # Password reset: http://localhost:3000/password-reset/{uid}/{token}/
```

## 📝 Configuration Highlights

### JWT Settings (`settings.py`)

```python
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(days=1),      # Production: 5-15 min
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),     # Production: 7-30 days
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
}

REST_AUTH = {
    "USE_JWT": True,
    "JWT_AUTH_COOKIE": "jwt-auth",
    "JWT_AUTH_REFRESH_COOKIE": "jwt-refresh-token",
    "JWT_AUTH_HTTPONLY": True,                      # XSS protection
    "JWT_AUTH_SAMESITE": "Lax",
    "JWT_AUTH_SECURE": not DEBUG,                   # HTTPS in production
    "SESSION_LOGIN": False,
}
```

### Frontend Configuration

```python
FRONTEND_URL = "http://localhost:3000/"
VERIFY_EMAIL_URL = "verify-email/"
PASSWORD_RESET_URL = "password-reset/"

CORS_ALLOWED_ORIGINS = ["http://localhost:3000"]
CORS_ALLOW_CREDENTIALS = True
```

## 🔄 Authentication Flow

### Registration & Email Verification

```
Frontend                 Backend                  Email
   |                        |                       |
   |--POST /registration/-->|                       |
   |<--201 + JWT tokens-----|                       |
   |                        |--Verification email-->|
   |                        |                       |
   |<----------User clicks link from email---------|
   |                        |                       |
   |--POST /confirm-email/->|                       |
   |    {key: "abc123"}     |                       |
   |<--200 + JWT tokens-----|                       |
   |  (email verified)      |                       |
```

### Password Reset

```
Frontend                 Backend                  Email
   |                        |                       |
   |--POST /password/reset->|                       |
   |<--200 OK---------------|                       |
   |                        |--Reset email--------->|
   |                        |                       |
   |<----------User clicks link from email---------|
   |                        |                       |
   |--POST /reset/confirm/->|                       |
   |  {uid, token, newpw}   |                       |
   |<--200 + JWT tokens-----|                       |
   |  (auto logged in)      |                       |
```

## 💻 Example Usage

### 1. Register User

```
curl -X POST http://localhost:8000/api/v1/auth/registration/ -H "Content-Type: application/json" -d '{"username": "johndoe", "email": "john@example.com", "password1": "SecurePass123!", "password2": "SecurePass123!"}'
```

**Response:**

```json
{
  "access": "eyJhbGci...",
  "refresh": "eyJhbGci...",
  "user": {
    "pk": 1,
    "username": "johndoe",
    "email": "john@example.com"
  }
}
```

### 2. Verify Email

Check console for email → extract key → verify:

```
curl -X POST http://localhost:8000/api/v1/auth/registration/account-confirm-email/ -H "Content-Type: application/json" -d '{"key": "MTp1c2VyOjE:1tABC..."}'
```

**Response:**

```json
{
  "detail": "Email confirmed successfully",
  "access": "eyJhbGci...",
  "refresh": "eyJhbGci..."
}
```

### 3. Login

```
curl -X POST http://localhost:8000/api/v1/auth/login/ -H "Content-Type: application/json" -d '{"username": "johndoe", "password": "SecurePass123!"}'
```

### 4. Access Protected Endpoint

```
curl -X GET http://localhost:8000/api/v1/auth/user/ -H "Authorization: Bearer eyJhbGci..."
```

### 5. Request Password Reset

```
curl -X POST http://localhost:8000/api/v1/auth/password/reset/ -H "Content-Type: application/json" -d '{"email": "john@example.com"}'
```

### 6. Confirm Password Reset

Check console for email → extract uid & token → reset:

```
curl -X POST http://localhost:8000/api/v1/auth/password/reset/confirm/ -H "Content-Type: application/json" -d '{"uid": "MQ", "token": "cxz3cl-abc123...", "new_password1": "NewPass456!", "new_password2": "NewPass456!"}'
```

**Response:**

```json
{
  "detail": "Password has been reset with the new password.",
  "access": "eyJhbGci...",
  "refresh": "eyJhbGci..."
}
```

## 🌐 Frontend Integration

### Cookie-Based (Recommended)

Automatic cookie handling with `credentials: 'include'`:

```javascript
// Login
const response = await fetch("http://localhost:8000/api/v1/auth/login/", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  credentials: "include", // Sends HttpOnly cookies
  body: JSON.stringify({ username: "johndoe", password: "SecurePass123!" }),
});

// Access protected endpoint
const userResponse = await fetch("http://localhost:8000/api/v1/auth/user/", {
  credentials: "include", // Cookies sent automatically
});
```

### Token-Based (Alternative)

Manual token management:

```javascript
// Store tokens
const data = await response.json();
localStorage.setItem("access_token", data.access);
localStorage.setItem("refresh_token", data.refresh);

// Use in requests
fetch("http://localhost:8000/api/v1/auth/user/", {
  headers: {
    Authorization: `Bearer ${localStorage.getItem("access_token")}`,
  },
});
```

### Email Verification Flow

```javascript
// Extract key from URL: http://localhost:3000/verify-email/{KEY}
const key = window.location.pathname.split("/").pop();

// Verify email
const response = await fetch("http://localhost:8000/api/v1/auth/registration/account-confirm-email/", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  credentials: "include",
  body: JSON.stringify({ key }),
});

// User is now verified and logged in
window.location.href = "/dashboard";
```

## 🧪 Testing Goals

The test suite validates the hybrid authentication system across all credential-issuing endpoints:

### Test Coverage

**5 Authentication Endpoints Tested:**

1. **Register** - User registration with JWT tokens
2. **Login** - User authentication with JWT tokens
3. **Refresh** - Token refresh functionality
4. **Email Verification** - Confirm email with auto-login
5. **Password Reset** - Reset password with auto-login

### Authentication Type Validation

Tests verify that credentials are returned with the correct `authType`:

- **Browser clients**: `authType: 'cookie'` with CSRF token
- **Mobile/Desktop apps**: `authType: 'bearer'` with access/refresh tokens

### CSRF Protection Testing

For `bearer` authentication on unsafe methods (PUT, PATCH, POST, DELETE):

- **Double-submit CSRF tokens** are required to protect against CSRF attacks
- **Logout endpoint** doesn't require CSRF protection (only needs valid refresh token)
- **Refresh endpoint** uses custom authentication class for CSRF validation

### Test Structure

```
users/tests/
├── conftest.py                    # Pytest fixtures
├── test_hybrid_auth.py            # Comprehensive hybrid auth tests
└── README_TESTS.md                # Test documentation
```

### Running Tests

```
# All tests
pytest users/tests/ -v

# Specific test file
pytest users/tests/test_hybrid_auth.py -v

# With output
pytest users/tests/ -v -s

# Coverage report
pytest users/tests/ --cov=users --cov-report=html
```

## 🔐 Custom Authentication Classes

The system uses two specialized authentication classes to handle different security requirements:

### CSRFCheckOnly Authentication

```python
class CSRFCheckOnly(BaseAuthentication):
    """
    Authentication class that ONLY enforces CSRF for browser requests.
    Does not actually authenticate - returns None to allow other auth or no auth.

    Useful for endpoints like token refresh that don't need user authentication
    but should still be protected against CSRF for browser clients.
    """
```

**Purpose:**

- Enforces CSRF protection for browser requests on unsafe HTTP methods
- Does not perform user authentication (returns `None`)
- Allows other authentication classes to handle user verification
- Used in token refresh endpoint where refresh token validation is handled separately

### JWTCookieAuthenticationWithCSRF

```python
class JWTCookieAuthenticationWithCSRF(JWTCookieAuthentication):
    """
    JWT Cookie authentication with CSRF protection for unsafe HTTP methods.

    Only enforces CSRF when JWT is in cookies (browser clients).
    Mobile/desktop apps using Authorization header are not affected.
    """
```

**Purpose:**

- Extends Django REST Framework's JWT cookie authentication
- Adds CSRF protection specifically for browser clients
- Mobile/desktop apps using Authorization headers bypass CSRF checks
- Ensures secure cookie-based authentication for web applications

### CSRF Protection Implementation

The system uses a **double-submit cookie pattern** for CSRF protection:

```python
def check_csrf(request):
    """
    Check CSRF token using double-submit cookie pattern.
    Raises PermissionDenied if CSRF check fails.
    """
    csrf_token_header = request.META.get('HTTP_X_CSRFTOKEN', '')
    csrf_token_cookie = request.COOKIES.get('csrftoken', '')

    if csrf_token_header != csrf_token_cookie:
        raise PermissionDenied('CSRF token mismatch.')
```

**How it works:**

1. Server sets CSRF token in cookie
2. Client includes same token in `X-CSRFToken` header
3. Server verifies both tokens match
4. Only enforced for browser clients on unsafe methods

## 🔒 Security Features

- ✅ **HttpOnly Cookies** - XSS protection for browser clients
- ✅ **CSRF Protection** - Double-submit pattern for web applications
- ✅ **Token Blacklisting** - Logout/rotation security
- ✅ **Cryptographically Secure Keys** - HMAC-based verification
- ✅ **Token Expiration** - Limited lifetime with refresh rotation
- ✅ **CORS Configuration** - Controlled origins
- ✅ **Password Validation** - Django validators
- ✅ **Client Detection** - Automatic browser vs mobile/desktop detection

## 🔧 CookiesOrAuthorizationJWTMixin

The core component that enables hybrid authentication by adapting JWT token delivery based on client type:

```python
class CookiesOrAuthorizationJWTMixin:
    """
    Mixin that adapts JWT token delivery based on client type.

    Default behavior (browsers): HttpOnly cookies with CSRF protection
    Mobile/Desktop apps: JSON tokens in response body
    """
```

### How It Works

The mixin overrides `finalize_response()` to modify the authentication response:

#### For Browser Clients:

```python
if is_browser:
    set_jwt_cookies(response, access, refresh)
    get_token(request)  # Generate CSRF token

    csrf_token = request.META.get("CSRF_COOKIE")
    response.data.pop("access", None)  # Remove tokens from JSON
    response.data.pop("refresh", None)
    response.data['csrf_token'] = csrf_token
    response.data['authType'] = 'cookie'
```

#### For Mobile/Desktop Clients:

```python
else:
    response.data['access'] = access
    response.data['refresh'] = refresh
    response.data['authType'] = 'bearer'
    response.cookies.clear()  # Remove cookies
```

### Key Features

- **Automatic Detection**: Uses `is_browser_request()` to determine client type
- **Token Extraction**: Handles tokens from both cookies and response data
- **Cookie Management**: Sets HttpOnly cookies for browsers, clears them for apps
- **CSRF Integration**: Generates and includes CSRF tokens for browser clients
- **Response Formatting**: Adds `authType` field to indicate authentication method

### Usage in Views

Applied to all authentication endpoints:

```python
class CustomLoginView(CookiesOrAuthorizationJWTMixin, LoginView):
    """Login view that adapts response format based on Origin header."""
    pass

class CustomRegisterView(CookiesOrAuthorizationJWTMixin, RegisterView):
    """Registration view that adapts response format based on Origin header."""
    pass
```

## 🎯 Custom Views Implementation

The system includes several custom views that extend Django REST Framework's authentication capabilities:

### CustomVerifyEmailView

```python
class CustomVerifyEmailView(CookiesOrAuthorizationJWTMixin, APIView):
    """
    Email verification view that adapts response format based on Origin header.
    CSRF exempt for better UX since the verification key already provides security.
    """
    permission_classes = [AllowAny]
    authentication_classes = []
```

**Key Features:**

- **No Authentication Required**: Verification key provides security
- **Auto-Login**: Returns JWT tokens after successful verification
- **Hybrid Response**: Adapts to browser vs mobile/desktop clients
- **HMAC Support**: Handles both database and HMAC-based verification keys

### CustomPasswordResetConfirmView

```python
class CustomPasswordResetConfirmView(CookiesOrAuthorizationJWTMixin, PasswordResetConfirmView):
    """
    Custom password reset confirm view that automatically logs the user in
    after successful password reset by returning JWT tokens.
    Response format adapts based on Origin header.
    CSRF exempt for better UX since the token in the URL already provides security.
    """
    permission_classes = [AllowAny]
    authentication_classes = []
```

**Key Features:**

- **CSRF Exempt**: Reset token provides sufficient security
- **Auto-Login**: Returns JWT tokens after successful password reset
- **UID Decoding**: Uses allauth's base36 decoder for user identification
- **Error Handling**: Comprehensive exception handling with detailed error messages

### CustomLogoutView

```python
class CustomLogoutView(APIView):
    """
    Custom logout view that handles both cookie-based (browser) and header-based (app) JWT authentication.
    CSRF exempt for better UX - logout is typically a safe operation.
    """
    authentication_classes = [JWTAuthentication, JWTCookieAuthentication]
    permission_classes = [AllowAny]
```

**Key Features:**

- **Dual Token Support**: Handles refresh tokens from both cookies and request body
- **Token Blacklisting**: Properly blacklists refresh tokens
- **Cookie Cleanup**: Removes authentication cookies for browser clients
- **Flexible Input**: Accepts refresh token from multiple sources

### CustomTokenRefreshView

```python
class CustomTokenRefreshView(CookiesOrAuthorizationJWTMixin, dj_rest_auth_refresh_view_class):
    """
    Token refresh view that supports both cookie and body-based refresh tokens.
    Uses dj-rest-auth's built-in cookie support with CSRF protection.

    CSRF protection is enforced via CSRFCheckOnly authentication class for browser requests.
    """
    authentication_classes = [CSRFCheckOnly, JWTCookieAuthentication]
```

**Key Features:**

- **CSRF Protection**: Uses `CSRFCheckOnly` for browser clients
- **Dual Token Support**: Handles both cookie and body-based refresh tokens
- **Hybrid Response**: Adapts response format based on client type
- **Built-in Integration**: Extends dj-rest-auth's refresh view functionality

### Standard Authentication Views

The system also includes custom versions of standard authentication views:

```python
class CustomLoginView(CookiesOrAuthorizationJWTMixin, LoginView):
    """Login view that adapts response format based on Origin header."""

class CustomRegisterView(CookiesOrAuthorizationJWTMixin, RegisterView):
    """Registration view that adapts response format based on Origin header."""
```

These views inherit the hybrid authentication behavior through the mixin while maintaining all standard functionality.

## 🚀 Production Checklist

- [ ] Set `DEBUG = False`
- [ ] Use environment variables for secrets
- [ ] Set `JWT_AUTH_SECURE = True` (HTTPS only)
- [ ] Configure proper email backend (SMTP, SendGrid)
- [ ] Update `ALLOWED_HOSTS`
- [ ] Shorten access token lifetime (5-15 minutes)
- [ ] Enable HTTPS
- [ ] Set up rate limiting
- [ ] Configure logging and monitoring
- [ ] Use PostgreSQL/MySQL (not SQLite)

## 📖 Additional Resources

- [Django REST Framework](https://www.django-rest-framework.org/)
- [dj-rest-auth](https://dj-rest-auth.readthedocs.io/)
- [django-allauth](https://docs.allauth.org/)
- [Simple JWT](https://django-rest-framework-simplejwt.readthedocs.io/)

## 🎓 Key Learnings

This tutorial demonstrates:

1. **JWT Authentication** - Stateless, scalable auth
2. **Token Rotation** - Security through refresh tokens
3. **Email Verification** - No auth required (key IS the auth)
4. **Auto-Login** - Seamless UX after verification/reset
5. **Cookie vs Token Auth** - Two approaches for different use cases
6. **Security Best Practices** - HttpOnly cookies, CSRF, CORS
7. **Testing** - Comprehensive pytest suite

## 📝 Project Structure

```
auth_demo/
├── auth_demo/
│   ├── settings.py          # Django settings
│   └── urls.py              # URL routing
├── users/
│   ├── adapters.py          # Custom email URLs
│   ├── api/v1/
│   │   └── views.py         # Custom auth views
│   └── tests/
│       ├── conftest.py      # Test fixtures
│       ├── test_email_verification.py
│       └── test_password_reset.py
├── manage.py
├── pyproject.toml           # uv dependencies
└── README.md

```

## 🤝 Contributing

This is a tutorial project. Feel free to fork, experiment, and learn!

---

**Happy Learning! 🚀**

For questions, open an issue on GitHub.
