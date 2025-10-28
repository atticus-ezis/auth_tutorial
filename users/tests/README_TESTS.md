There are only 5 endpoints which issue authentication credentials

1. Register
2. Login
3. Refresh
4. confrim verify email
5. confirm reset pass

The tests verify that these credentials are returned correctly, tokens should have authType ('cookie') for browser and authType ('bearer') for App.

For 'bearer' endpoints that use [PUT, PATCH, POST, DELETE], a double submit csrf tokens is also required to protect against CSRF.

Logout:
Logout doesn't need csrf protection or a valid access token since this operation isn't a security threat. It only needs a valid refresh token to blacklist. Here we'll use a custom view.

Refresh:
Only needs a valid refresh token. For 'bearer' this token must be submitted in the request body, for 'cookie' the refresh token and csrf double sumbit are required. We'll use a custom authentication class for this case.
