# Django JWT Authentication Tutorial

Complete implementation of JWT-based authentication using Django REST Framework, dj-rest-auth, and django-allauth with email verification and password reset.

## 🎯 Features

- ✅ User registration with JWT tokens
- ✅ Email verification (HMAC-based)
- ✅ Password reset with auto-login
- ✅ Token refresh and blacklisting
- ✅ HttpOnly cookies for security
- ✅ No auth required for public endpoints
- ✅ Comprehensive test suite

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

## 🔑 Key Implementation Details

### Custom Views (No Auth Required)

Both email verification and password reset **don't require JWT authentication**:

```python
class CustomVerifyEmailView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []  # No auth/CSRF required

    def post(self, request):
        # Verification key IS the authentication
        # Returns JWT tokens for auto-login
```

**Why?**

- User may have logged out or tokens expired
- The verification key/reset token is cryptographically secure
- Standard practice for email-based verification

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

## 🧪 Testing

### Test Structure

```
users/tests/
├── conftest.py                    # Pytest fixtures
├── test_email_verification.py     # 8 tests
└── test_password_reset.py         # 4 tests
```

### Running Tests

```
# All tests
pytest users/tests/ -v

# Specific test
pytest users/tests/test_email_verification.py::TestEmailVerification::test_verify_email_with_valid_key_returns_tokens -v

# With output
pytest users/tests/ -v -s

# Coverage report
pytest users/tests/ --cov=users --cov-report=html
```

### Manual Testing Script

```
# Terminal 1: Start server
python manage.py runserver

# Terminal 2: Run test script
sh test_password_reset_live.sh
```

## 🔒 Security Features

- ✅ **HttpOnly Cookies** - XSS protection
- ✅ **CSRF Protection** - For session-based requests
- ✅ **Token Blacklisting** - Logout/rotation security
- ✅ **Cryptographically Secure Keys** - HMAC-based verification
- ✅ **Token Expiration** - Limited lifetime
- ✅ **CORS Configuration** - Controlled origins
- ✅ **Password Validation** - Django validators

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

- [PASSWORD_RESET_FLOW.md](./PASSWORD_RESET_FLOW.md) - Detailed flow documentation
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
