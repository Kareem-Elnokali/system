"""Django app configuration for the MFA app"""
from django.apps import AppConfig
class MfaConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'mfa'
    verbose_name = 'Multi-Factor Authentication'
    def ready(self):
        from . import signals
