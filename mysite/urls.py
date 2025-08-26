"""
URL configuration for mysite project.
The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
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
from mfa import views as mfa_views
from django.views.generic import TemplateView, RedirectView
from django.conf import settings
from django.conf.urls.static import static
from . import views
urlpatterns = [
    path('admin/', RedirectView.as_view(pattern_name='mfa:admin_dashboard', permanent=False)),
    path('django-admin/', admin.site.urls),
    path('', views.home, name='home'),
    path('about/', views.about, name='about'),
    path('contact/', views.contact, name='contact'),
    path('accounts/', include('allauth.urls')),
    path('mfa/', include(('mfa.urls', 'mfa'), namespace='mfa')),
    path('passkeys/auth/begin', mfa_views.passkey_auth_begin, name='passkeys_auth_begin_override'),
    path('passkeys/auth/complete', mfa_views.passkey_auth_complete, name='passkeys_auth_complete_override'),
    path('passkeys/', include(('passkeys.urls', 'passkeys'), namespace='passkeys')),
]
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
