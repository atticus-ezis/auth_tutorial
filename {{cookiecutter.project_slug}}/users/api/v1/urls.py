from django.http import HttpResponseRedirect
from django.conf import settings
from django.urls import path
from dj_rest_auth.registration.views import ResendEmailVerificationView
from dj_rest_auth.views import PasswordResetView, UserDetailsView

from users.api.v1.views import (
    CustomLoginView,
    CustomLogoutView,
    CustomPasswordChangeView,
    CustomPasswordResetConfirmView,
    CustomRegisterView,
    CustomTokenRefreshView,
    CustomVerifyEmailView,
)


def password_reset_placeholder(request, uidb64, token):
    frontend_url = f"{settings.FRONTEND_URL}{settings.PASSWORD_RESET_URL}"
    return HttpResponseRedirect(f"{frontend_url}?uid={uidb64}&token={token}")


def account_confirm_placeholder(request, key):
    frontend_url = f"{settings.FRONTEND_URL}{settings.VERIFY_EMAIL_URL}"
    return HttpResponseRedirect(f"{frontend_url}?key={key}")

urlpatterns = [
    path('login/', CustomLoginView.as_view(), name='rest_login'),
    path('logout/', CustomLogoutView.as_view(), name='rest_logout'),
    path('token/refresh/', CustomTokenRefreshView.as_view(), name='rest_token_refresh'),
    path('registration/', CustomRegisterView.as_view(), name='rest_register'),
    path('registration/resend-email/', ResendEmailVerificationView.as_view(), name='resend_email'),
    path('registration/account-confirm-email/', CustomVerifyEmailView.as_view(), name='account_confirm_email_api'),
    path('registration/account-confirm-email/<str:key>/', account_confirm_placeholder, name='account_confirm_email'),
    path('password/change/', CustomPasswordChangeView.as_view(), name='rest_password_change'),
    path('password/reset/', PasswordResetView.as_view(), name='rest_password_reset'),
    path('password/reset/confirm/', CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm_api'),
    path('password-reset-confirm/<uidb64>/<token>/', password_reset_placeholder, name='password_reset_confirm'),
    path('details/', UserDetailsView.as_view(), name='user_details'),
]