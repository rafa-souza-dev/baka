"""
URL configuration for config project.

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
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from authentication.api.viewsets import CreateUserView, ChangePasswordAPIView
from authentication.views import PasswordResetView

urlpatterns = [
    path('admin/', admin.site.urls),

    # auth
    path('api/sessions/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/sessions/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/change-password/', ChangePasswordAPIView.as_view(), name='change_password'),
    path('api/reset-password/', include('django_rest_passwordreset.urls', namespace='password_reset')),
    path('reset-password-confirm/', PasswordResetView.as_view(), name='password_reset_confirm_form'),

    # users
    path('api/users/', CreateUserView.as_view(), name='create_user'),
]
