"""
URL configuration for {{cookiecutter.project_name}} project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from users.api.v1.views import (
    CustomVerifyEmailView, 
    CustomPasswordResetConfirmView,
    CustomLoginView,
    CustomRegisterView,
    CustomLogoutView,
    CustomTokenRefreshView,
)
from django.views.generic import RedirectView
from django.http import HttpResponseRedirect

from django.conf import settings

urlpatterns = [
    path('admin/', admin.site.urls),
    path(
        'api/v1/auth/', 
        include(
            [
                # Custom views MUST come before dj_rest_auth.urls to override defaults
                path("login/", CustomLoginView.as_view(), name="rest_login"),
                path("logout/", CustomLogoutView.as_view(), name="rest_logout"),
                path("registration/", CustomRegisterView.as_view(), name="rest_register"),
                path("token/refresh/", CustomTokenRefreshView.as_view(), name="token_refresh"),
                path(
                    "registration/account-confirm-email/",
                    CustomVerifyEmailView.as_view(),
                    name="account_confirm_email",
                ),
                path(
                    "password/reset/confirm/",
                    CustomPasswordResetConfirmView.as_view(),
                    name="custom_rest_password_reset_confirm",
                ),
                path(
                    "password-reset-confirm/<uidb64>/<token>/",
                    lambda request, uidb64, token: HttpResponseRedirect(
                        f"{settings.FRONTEND_URL}{settings.PASSWORD_RESET_URL}?uid={uidb64}&token={token}"
                    ),
                    name="password_reset_confirm",
                ),
                # Default dj-rest-auth URLs (remaining endpoints)
                path('', include('dj_rest_auth.urls')),
                path('registration/', include('dj_rest_auth.registration.urls')),
            ]

        )
    ) 
]
