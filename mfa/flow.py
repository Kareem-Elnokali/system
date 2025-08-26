"""Core MFA flow helpers
This module contains small helpers that kick off MFA after a successful
username/password authentication. It chooses the first applicable factor
based on project-wide settings and the user's registered devices, and
stores state in the session using well-defined keys.
Session keys:
- `SESSION_USER_ID`: the user id currently undergoing MFA (pending login)
- `SESSION_EMAIL_CODE`: last email OTP sent to the user
- `SESSION_EMAIL_EXPIRES`: ISO timestamp when the email OTP expires
- `SESSION_SMS_OTP_CODE`: last SMS OTP code (dev/provider-dependent)
- `SESSION_PHONE_NUMBER_TO_VERIFY`: phone number being verified/linked
"""
from __future__ import annotations
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
import random
from datetime import timedelta
from .models import MFASettings
SESSION_USER_ID = 'mfa_pending_user_id'
SESSION_EMAIL_CODE = 'mfa_email_code'
SESSION_EMAIL_EXPIRES = 'mfa_email_expires_at'
SESSION_SMS_OTP_CODE = 'mfa_sms_otp_code'
SESSION_PHONE_NUMBER_TO_VERIFY = 'mfa_phone_to_verify'
def start_mfa(request, user, use_email_otp: bool = True) -> str:
    """
    Initialize MFA flow for a user and return the URL name to redirect to.
    Returns a URL name like `'mfa:verify_totp'`, `'mfa:verify_email'`, or an
    empty string to indicate "no MFA required" (caller should proceed to login).
    Decision order:
    1) If the site forces a method picker (`MFASettings.always_show_method_picker`),
       store pending user in session and send the user to `'mfa:choose_method'`.
    2) If the user has a confirmed TOTP device, prefer TOTP verification.
    3) Otherwise, if `use_email_otp` is True and the user has an email, send an
       email OTP and direct them to `'mfa:verify_email'`.
    4) Otherwise, return '' to indicate no MFA will be performed.
    Note: If sending the email fails and `settings.MFA_FAIL_OPEN` is True
    (default), we fail-open by returning '' so the caller can log the user in.
    """
    settings_obj = MFASettings.load()
    if settings_obj.always_show_method_picker:
        request.session[SESSION_USER_ID] = user.id
        request.session.modified = True
        return 'mfa:choose_method'
    try:
        totp_device = user.mfa_devices.filter(confirmed=True).first()
    except Exception:
        totp_device = None
    if totp_device:
        request.session[SESSION_USER_ID] = user.id
        request.session.modified = True
        return 'mfa:verify_totp'
    if use_email_otp and getattr(user, 'email', None):
        code = f"{random.randint(0, 999999):06d}"
        request.session[SESSION_USER_ID] = user.id
        request.session[SESSION_EMAIL_CODE] = code
        request.session[SESSION_EMAIL_EXPIRES] = (timezone.now() + timedelta(minutes=5)).isoformat()
        request.session.modified = True
        try:
            try:
                user_key = getattr(getattr(user, 'mfa_profile', None), 'safety_key', '')
            except Exception:
                user_key = ''
            safety_phrase = user_key or getattr(settings, 'SAFETY_PHRASE', '')
            msg_lines = [
                f"Your one-time code is: {code}",
                "This code expires in 5 minutes.",
            ]
            if safety_phrase:
                msg_lines += [
                    "",
                    f"Security Key: {safety_phrase}",
                    "Make sure this matches the key shown on our site.",
                    "If it doesn't match, stop. It could be a fake email.",
                ]
            send_mail(
                subject=getattr(settings, 'MFA_EMAIL_SUBJECT', 'Your login code'),
                message="\n".join(msg_lines),
                from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', None),
                recipient_list=[user.email],
                fail_silently=False,
            )
        except Exception:
            if getattr(settings, 'MFA_FAIL_OPEN', True):
                return ''
            raise
        return 'mfa:verify_email'
    return ''
