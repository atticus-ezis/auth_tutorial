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
from django.urls import path, include, re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title="{{ cookiecutter.project_name }} API",
        default_version="v1",
        description=(
            "Dual delivery JWT:\n"
            "- Browser: JWT in cookie + double-submit CSRF (X-CSRFToken)\n"
            "- App/SDK: Bearer tokens\n"
            "Use 'X-Client: browser|app'."
        ),
    ),
    public=True,
    permission_classes=[permissions.AllowAny],  # don't auth-gate the schema
)


urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/auth/", include("users.api.v1.urls")),
]

# API DOCS
urlpatterns += [
    re_path(
        r"^api/docs(?P<format>\.json|\.yaml)$",
        schema_view.without_ui(cache_timeout=0),
        name="schema-json",
    ),
    path(
        "api/docs/",
        schema_view.with_ui("swagger", cache_timeout=0),
        name="schema-swagger-ui",
    ),
    path(
        "api/redoc/", schema_view.with_ui("redoc", cache_timeout=0), name="schema-redoc"
    ),
]
