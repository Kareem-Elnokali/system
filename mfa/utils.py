"""MFA utility functions
This module provides small building blocks used across the MFA app:
- TOTP secret generation and code verification
- Backup codes creation and hashing (with normalization + legacy support)
- Phone number normalization and a development-only SMS OTP helper
- Server-side verification for Cloudflare Turnstile and Google reCAPTCHA v2
"""
import base64
import hashlib
import hmac
import os
import struct
import time
from urllib.parse import quote
import json
import urllib.request
import urllib.parse
from django.conf import settings
from django.urls import reverse
import random
import logging
logger = logging.getLogger(__name__)
def _int_to_bytes(i: int) -> bytes:
    return struct.pack('>Q', i)
def base32_secret(raw: bytes | None = None, length: int = 20) -> str:
    """Generate a base32-encoded secret suitable for TOTP.
    If raw is provided, encode it; otherwise generate cryptographically strong bytes.
    """
    if raw is None:
        raw = os.urandom(length)
    return base64.b32encode(raw).decode('utf-8').replace('=', '')
def totp_code(secret_b32: str, time_step: int = 30, digits: int = 6, t: int | None = None) -> str:
    """Compute an RFC 6238-compatible TOTP for the given base32 secret.
    `t` is the Unix timestamp used for the window (defaults to now). We pad the
    secret as needed to be valid base32 and then perform dynamic truncation.
    """
    if t is None:
        t = int(time.time())
    counter = int(t // time_step)
    pad = '=' * ((8 - (len(secret_b32) % 8)) % 8)
    key = base64.b32decode(secret_b32 + pad, casefold=True)
    msg = _int_to_bytes(counter)
    hs = hmac.new(key, msg, hashlib.sha1).digest()
    offset = hs[-1] & 0x0F
    code_int = (struct.unpack('>I', hs[offset:offset+4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return f"{code_int:0{digits}d}"
def verify_totp(secret_b32: str, code: str, window: int = 1, time_step: int = 30, digits: int = 6) -> bool:
    """Verify a user-provided `code` against the secret within a +/- window.
    Basic input checks reject non-digit or wrong-length codes early. The
    sliding window improves UX to account for small clock drift.
    """
    code = (code or '').strip()
    if not code.isdigit() or not (6 <= len(code) <= 8):
        return False
    now = int(time.time())
    for w in range(-window, window + 1):
        if totp_code(secret_b32, time_step=time_step, digits=digits, t=now + w * time_step) == code:
            return True
    return False
def provisioning_uri(secret_b32: str, account_name: str, issuer: str) -> str:
    label = f"{issuer}:{account_name}"
    return (
        f"otpauth://totp/{quote(label)}?secret={secret_b32}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
    )
def hash_backup_code(code: str) -> str:
    """Return salted SHA256 of a normalized backup code.
    Normalization: uppercase, strip, remove spaces and hyphens.
    """
    code = (code or '').strip().upper().replace(' ', '').replace('-', '')
    salt = 'mfa-salt-v1'
    return hashlib.sha256((salt + ':' + code).encode()).hexdigest()
def legacy_hash_backup_code(code: str) -> str:
    """Legacy salted SHA256 without normalization (kept for backward compatibility)."""
    code = (code or '').strip()
    salt = 'mfa-salt-v1'
    return hashlib.sha256((salt + ':' + code).encode()).hexdigest()
def generate_backup_codes(user, count: int = 10) -> list[str]:
    """Generate backup codes for a user and save them to database"""
    from .models import BackupCode
    codes = []
    for _ in range(count):
        raw = base64.b32encode(os.urandom(4)).decode('utf-8').rstrip('=')
        raw = ''.join(ch for ch in raw if ch.isalnum())[:8].upper()
        code = raw[:4] + '-' + raw[4:8]
        codes.append(code)
        # Create BackupCode object
        BackupCode.objects.create(
            user=user,
            code_hash=hash_backup_code(code)
        )
    return codes
def normalize_phone(phone: str) -> str:
    """Normalize phone to E.164. Defaults to Egypt (+20) if local 0-leading is used.
    Uses settings.DEFAULT_COUNTRY_DIAL_CODE if provided (digits only, e.g., '20').
    """
    if not phone:
        return phone
    p = str(phone).strip().replace(' ', '')
    if p.startswith('00'):
        p = '+' + p[2:]
    if p.startswith('+'):
        return p
    if p.startswith('0'):
        dial = getattr(settings, 'DEFAULT_COUNTRY_DIAL_CODE', '20')
        return f"+{dial}{p[1:]}"
    return '+' + p
def send_sms_otp(phone_number: str) -> tuple[str | None, str | None]:
    """Development SMS OTP generator. No external provider is used.
    Returns: (code, error_message). In DEBUG or when FORCE_DEV_OTP, returns a 6-digit code.
    In production without a provider, returns an error.
    """
    try:
        to_number = normalize_phone(phone_number)
        dev_mode = getattr(settings, 'DEBUG', False) or getattr(settings, 'FORCE_DEV_OTP', False)
        if dev_mode:
            code = f"{random.randint(0, 999999):06d}"
            logger.warning("[DEV ONLY] Returning OTP '%s' for %s (no SMS sent)", code, to_number)
            print(f"[DEV ONLY] SMS OTP to {to_number} (not sent): {code}")
            return code, None
        msg = "SMS provider is not configured. Enable Firebase Phone Auth or another provider."
        logger.error(msg)
        return None, msg
    except Exception as e:
        logger.error(f"Unexpected error generating SMS OTP: {e}")
        return None, str(e)
TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
def turnstile_enabled() -> bool:
    """Feature toggle based on presence of site and secret keys in settings."""
    site = getattr(settings, 'TURNSTILE_SITE_KEY', None) or getattr(settings, 'CLOUDFLARE_TURNSTILE_SITE_KEY', None)
    secret = getattr(settings, 'TURNSTILE_SECRET_KEY', None) or getattr(settings, 'CLOUDFLARE_TURNSTILE_SECRET_KEY', None)
    return bool(site and secret)
def turnstile_site_key() -> str | None:
    return getattr(settings, 'TURNSTILE_SITE_KEY', None) or getattr(settings, 'CLOUDFLARE_TURNSTILE_SITE_KEY', None)
def verify_turnstile(request) -> tuple[bool, list[str]]:
    """Server-side verification for Cloudflare Turnstile.
    Returns (ok, error_codes)
    """
    try:
        token = request.POST.get('cf-turnstile-response') or request.POST.get('g-recaptcha-response')
        if not token:
            return False, ['missing-input']
        secret = getattr(settings, 'TURNSTILE_SECRET_KEY', None) or getattr(settings, 'CLOUDFLARE_TURNSTILE_SECRET_KEY', None)
        data = urllib.parse.urlencode({
            'secret': secret,
            'response': token,
            'remoteip': request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip() or request.META.get('REMOTE_ADDR') or '',
        }).encode('utf-8')
        req = urllib.request.Request(TURNSTILE_VERIFY_URL, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            payload = json.loads(resp.read().decode('utf-8'))
        success = bool(payload.get('success'))
        return success, payload.get('error-codes', []) or []
    except Exception as e:
        logger.error(f"Turnstile verify error: {e}")
        return False, ['verify-error']
RECAPTCHA_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'
def recaptcha_site_key() -> str | None:
    return getattr(settings, 'RECAPTCHA_SITE_KEY', None) or getattr(settings, 'GOOGLE_RECAPTCHA_SITE_KEY', None)
def recaptcha_enabled() -> bool:
    site = recaptcha_site_key()
    secret = getattr(settings, 'RECAPTCHA_SECRET_KEY', None) or getattr(settings, 'GOOGLE_RECAPTCHA_SECRET_KEY', None)
    return bool(site and secret)
def verify_recaptcha(request) -> tuple[bool, list[str]]:
    """Server-side verification for Google reCAPTCHA v2. Returns (ok, error_codes)"""
    try:
        token = request.POST.get('g-recaptcha-response')
        if not token:
            return False, ['missing-input']
        secret = getattr(settings, 'RECAPTCHA_SECRET_KEY', None) or getattr(settings, 'GOOGLE_RECAPTCHA_SECRET_KEY', None)
        data = urllib.parse.urlencode({
            'secret': secret,
            'response': token,
            'remoteip': request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip() or request.META.get('REMOTE_ADDR') or '',
        }).encode('utf-8')
        req = urllib.request.Request(RECAPTCHA_VERIFY_URL, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            payload = json.loads(resp.read().decode('utf-8'))
        success = bool(payload.get('success'))
        return success, payload.get('error-codes', []) or []
    except Exception as e:
        logger.error(f"reCAPTCHA verify error: {e}")
        return False, ['verify-error']
def get_mfa_user_redirect() -> str:
    """Return the default post-auth redirect for normal users within MFA.
    Uses MFA-specific settings with safe defaults to MFA routes to avoid coupling
    to the main site's LOGIN_REDIRECT_URL.
    """
    return getattr(settings, 'MFA_LOGIN_REDIRECT_URL', reverse('mfa:profile'))
def get_mfa_admin_redirect() -> str:
    """Return the default post-auth redirect for admin/staff within MFA."""
    return getattr(settings, 'MFA_ADMIN_REDIRECT_URL', reverse('mfa:admin_dashboard'))
def get_mfa_login_url() -> str:
    """Return the MFA-local login URL to avoid using global LOGIN_URL."""
    return getattr(settings, 'MFA_LOGIN_URL', reverse('mfa:login'))
def generate_safety_key(length: int = 8) -> str:
    """Generate a short human-readable key (lowercase letters + digits).
    Length is clamped to 6–8 characters to align with DB constraints.
    Not cryptographically sensitive; used only as an anti-phishing visual.
    """
    alphabet = 'abcdefghjkmnpqrstuvwxyz23456789'
    length = max(6, min(8, int(length or 8)))
    return ''.join(random.choice(alphabet) for _ in range(length))
