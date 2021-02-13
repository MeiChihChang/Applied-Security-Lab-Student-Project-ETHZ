"""webserver URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
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
from django.urls import path
from django.views.generic import TemplateView

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('admin/', admin.site.urls),
    path('login/', views.AuthUserView.as_view(), name='login'),
    path('logout/', views.LogoutUserView.as_view(), name='logout'),
    path('update/', views.UpdateUserView.as_view(), name='update'),
    path('userinfo/', views.GetUserInfoView.as_view(), name='userinfo'),
    path('refresh_token/', views.RefreshTokenView.as_view(), name='refresh_token'),
    path('new_token/', views.NewTokenView.as_view(), name='new_token'),
    path('revoke_token/', views.RevokeTokenView.as_view(), name='revoke_token'),
    path('generate_cert/', views.GenerateCertView.as_view(), name='generate_cert'),
    path('verify_cert/', views.VerifyCertView.as_view(), name='verify_cert'),
    path('revoke_cert/', views.RevokeCertView.as_view(), name='revoke_cert'),
    path('status_cert/', views.StatusCertView.as_view(), name='status_cert'),
]
