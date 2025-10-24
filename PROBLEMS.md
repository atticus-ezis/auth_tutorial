### Validation Issues

# I want to use cookies + csrf tokens for browsers to prevent XSS from getting access to my tokens in the JSON Body. But for apps I want simple JWT

# If I use cookies then I must also use csrf tokens to prevent csrf requests. This can be done with double submit method where csrftoken is attached as cookie, then extracted and placed in a new header (X-CSRFToken). This works because cross sites can't customize headers and extract info thanks to same origin policy enforced by browsers. Note: csrf must be readable (not http only) tokens must be hidden (http only).

(Can't I rely on same_site? and CORS to prevent csrf? why do I still need a token)
SameSite: restricts which sites recieve cookies (once cookies sent hackers can use cross site)
CORS: restricts which sites recicve your responses (requests can still be made cross site)

XSS - input sanitization, CSP (content security policy)

Problem - I'm using JWTCookieAuthentication (not SessionAuthentication), DRF is bypassing Django's CSRF middleware.

Solution - I need a custom authorization class that enforces csrf token for JWTCookieAuthentication to use inplace of JWTCookieAuthentication.

Problem - I need to customize the authorization method to use cookies if available.

Solution - Create a mixin that detects desired authorization method and returns tokens accordingly.

Is a hybrid approach where header and origin determine the authentication method secure?
Scenario 1:
Attacker wants to use XSS to get an acceess token. They can spoof the origin from a non browser source or spoof the header to request to get eaither, a simple JWT or cookie response. Since cookies are more secure they could return simple JWT then extract these tokens from the body.
Why is it still secure.
They can only spoof authorization on certain endpoints, register, login, refresh, reset password, verify email confirmation links. As these are the only endpoints that issue authorization. For them to get a successfull response it isn't enough to 'trick' the backend into returning cookies or jwt they would also need valid user credientials such as username password or email (for links).
This assumes the point at which authorization method is determined (cookie or JWT) is secure. The only way this can be exploited is if a hacker returns simple JWT to a broswer and uses XSS to read the tokens. But they will lack the basic authentication details to do this

XSS attackers cannot make a request appear as a non-browser (browser protects origin)
