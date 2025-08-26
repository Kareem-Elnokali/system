from __future__ import annotations
import logging
from django.dispatch import receiver
from django.contrib.auth.signals import user_logged_in
from django.http import HttpRequest
from .models import MFALog
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from .models import Profile, MFASettings
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
import json

logger = logging.getLogger(__name__)
User = get_user_model()

def _client_ip(request: HttpRequest | None) -> str | None:
    try:
        if not request:
            return None
        xff = request.META.get('HTTP_X_FORWARDED_FOR')
        if xff:
            return xff.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')
    except Exception:
        return None

@receiver(user_logged_in)
def log_login_success(sender, request, user, **kwargs):
    """Record a terminal login success for any successful authentication.
    - Method is 'social' if the user has any linked social accounts, else 'password'.
    - If the request path starts with /admin, tag details as 'admin'.
    """
    try:
        path = (getattr(request, 'path', '') or '')
        log_user = user if (user is not None and getattr(user, 'pk', None)) else (
            request.user if (getattr(request, 'user', None) is not None and getattr(request.user, 'is_authenticated', False)) else None
        )
        if path.startswith('/admin') or path.startswith('/mfa/admin'):
            method = 'password'
            details = 'admin'
        else:
            if getattr(user, 'socialaccount_set', None) and user.socialaccount_set.filter(provider='google').exists():
                method = 'Google'
            else:
                method = 'password'
            details = ''
        MFALog.objects.create(
            user=log_user,
            event='login_success',
            method=method,
            ip_address=_client_ip(request),
            user_agent=(request.META.get('HTTP_USER_AGENT') if request else ''),
            details=details,
        )
        logger.debug('MFALog login_success recorded for user=%s method=%s details=%s', getattr(log_user, 'id', None), method, details)
        logger.debug('MFALog login_success recorded for user=%s method=%s details=%s', getattr(user, 'id', None), method, details)
    except Exception as e:
        logger.warning('Failed to record MFALog login_success: %s', e)

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Create a Profile for new users."""
    if created:
        try:
            Profile.objects.create(user=instance)
            logger.info(f"Profile created for user {instance.username}")
        except Exception as e:
            logger.error(f"Failed to create profile for user {instance.username}: {e}")

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """Ensure the user's profile is saved when the user is saved."""
    try:
        if hasattr(instance, 'profile'):
            instance.profile.save()
        else:
            # Create profile if it doesn't exist
            Profile.objects.get_or_create(user=instance)
    except Exception as e:
        logger.error(f"Failed to save profile for user {instance.username}: {e}")

@receiver(post_save, sender=MFALog)
def broadcast_mfa_event(sender, instance, created, **kwargs):
    """Broadcast new MFA events to WebSocket clients."""
    if created:
        try:
            channel_layer = get_channel_layer()
            if channel_layer:
                # Determine event type for styling
                event_type = 'success'
                if 'failure' in instance.event:
                    event_type = 'failure'
                elif 'rate_limit' in instance.event or 'lockout' in instance.event:
                    event_type = 'warning'
                
                # Get method from event
                method = 'Unknown'
                if 'email' in instance.event:
                    method = 'Email OTP'
                elif 'totp' in instance.event:
                    method = 'TOTP'
                elif 'passkey' in instance.event:
                    method = 'Passkey'
                elif 'backup' in instance.event:
                    method = 'Backup Code'
                elif 'sms' in instance.event:
                    method = 'SMS'
                elif instance.method:
                    method = instance.method
                
                event_data = {
                    'type': event_type,
                    'event': instance.event,
                    'user': instance.user.username if instance.user else 'Unknown',
                    'method': method,
                    'ip': instance.ip_address or 'Unknown',
                    'timestamp': instance.created_at.isoformat(),
                    'details': instance.details or ''
                }
                
                async_to_sync(channel_layer.group_send)(
                    'admin_monitoring',
                    {
                        'type': 'mfa_event',
                        'event_data': event_data
                    }
                )
        except Exception as e:
            logger.error(f"Failed to broadcast MFA event: {e}")

def ensure_mfa_settings():
    """Ensure MFASettings singleton exists."""
    try:
        settings, created = MFASettings.objects.get_or_create(pk=1)
        if created:
            logger.info("MFASettings singleton created")
        return settings
    except Exception as e:
        logger.error(f"Failed to ensure MFASettings: {e}")
        return None
