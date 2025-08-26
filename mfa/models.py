"""Database models for the MFA app
Models:
- `MFADevice`: stores per-user TOTP authenticators.
- `BackupCode`: stores hashed backup codes and usage state.
- `MFALog`: lightweight audit trail for MFA-related actions.
- `MFASettings`: singleton feature toggles for enabled factors.
- `Profile`: simple per-user profile holding phone number.
"""
from __future__ import annotations
from django.conf import settings
from django.db import models, transaction
from django.utils import timezone
from .utils import base32_secret, hash_backup_code, legacy_hash_backup_code, generate_safety_key
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
import json
from django.contrib.sessions.models import Session
class MFADevice(models.Model):
    """A user's authenticator device (TOTP secret + confirmation flag)."""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='mfa_devices')
    name = models.CharField(max_length=100, default='Authenticator')
    secret = models.CharField(max_length=64, editable=False)
    confirmed = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)
    class Meta:
        indexes = [
            models.Index(fields=['user', 'confirmed']),
        ]
        unique_together = [('user', 'name')]

    def save(self, *args, **kwargs):
        if not self.secret:
            self.secret = base32_secret()
        return super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"MFADevice({self.user}, {self.name}, confirmed={self.confirmed})"


class BackupCode(models.Model):
    """A single backup code for a user, stored as a salted SHA-256 hash.
    Note: hashing uses normalization (uppercase, no spaces/hyphens). `verify_code`
    also supports a legacy hashing method for backward compatibility.
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='mfa_backup_codes')
    code_hash = models.CharField(max_length=64, unique=True)
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)
    used_at = models.DateTimeField(null=True, blank=True)
    class Meta:
        indexes = [
            models.Index(fields=['user', 'used']),
        ]
    def mark_used(self):
        """Idempotently mark a code as used and timestamp it."""
        if not self.used:
            self.used = True
            self.used_at = timezone.now()
            self.save(update_fields=['used', 'used_at'])
    def verify_code(self, raw_code: str) -> bool:
        """Compare provided raw code (any case, with/without hyphens/spaces) against stored hash.
        Accepts both normalized (current) and legacy (pre-normalization) hash formats.
        """
        try:
            new_h = hash_backup_code(raw_code)
            if self.code_hash == new_h:
                return True
            old_h = legacy_hash_backup_code(raw_code)
            return self.code_hash == old_h
        except Exception:
            return False
class MFALog(models.Model):
    """Simple audit log for MFA actions to support admin visibility."""
    EVENT_CHOICES = [
        ('choose_method', 'Choose Method'),
        ('email_code_sent', 'Email Code Sent'),
        ('email_verify_success', 'Email Verify Success'),
        ('email_verify_failure', 'Email Verify Failure'),
        ('totp_verify_success', 'TOTP Verify Success'),
        ('totp_verify_failure', 'TOTP Verify Failure'),
        ('backup_codes_generated', 'Backup Codes Generated'),
        ('backup_code_used', 'Backup Code Used'),
        ('totp_linked', 'TOTP Linked'),
        ('totp_unlinked', 'TOTP Unlinked'),
    ]
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='mfa_logs')
    event = models.CharField(max_length=64, choices=EVENT_CHOICES)
    method = models.CharField(max_length=32, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    details = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    class Meta:
        indexes = [
            models.Index(fields=['event', 'created_at']),
            models.Index(fields=['user', 'created_at']),
        ]
        ordering = ['-created_at']
    def __str__(self) -> str:
        return f"MFALog(user={self.user_id}, event={self.event}, method={self.method}, at={self.created_at:%Y-%m-%d %H:%M:%S})"
class MFASettings(models.Model):
    """A tiny singleton to toggle which MFA types the site enables.
    Keep it simple so it can be used across different projects.
    """
    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    enable_totp = models.BooleanField(default=True)
    enable_email = models.BooleanField(default=True)
    enable_passkeys = models.BooleanField(default=True)
    enable_sms = models.BooleanField(default=True)
    enable_backup_codes = models.BooleanField(default=True)
    always_show_method_picker = models.BooleanField(default=True)
    report_enabled = models.BooleanField(default=False)
    report_recipients = models.TextField(blank=True, default="")
    report_frequency_days = models.PositiveSmallIntegerField(default=7)
    report_csv_days = models.PositiveSmallIntegerField(default=7)
    report_next_send_at = models.DateTimeField(null=True, blank=True)
    report_last_sent_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    class Meta:
        verbose_name = 'MFA Settings'
        verbose_name_plural = 'MFA Settings'
    def __str__(self) -> str:
        return 'MFA Settings'
    @classmethod
    def load(cls):
        """Return the singleton settings row, creating if needed, atomically.
        Also enforces that only one row exists and that email remains enabled.
        """
        with transaction.atomic():
            obj, _created = cls.objects.select_for_update().get_or_create(pk=1)
            # Hard-enforce singleton by deleting any stray rows in the same tx
            cls.objects.exclude(pk=obj.pk).delete()
            if not obj.enable_email:
                obj.enable_email = True
                obj.save(update_fields=["enable_email", "updated_at"])
            return obj
class Profile(models.Model):
    """Basic user profile storing a phone number used for SMS OTP."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='mfa_profile')
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    safety_key = models.CharField(max_length=8, blank=True, null=True, unique=True)
    def __str__(self):
        return f'{self.user.username} Profile'
    class Meta:
        pass
@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    """Ensure every `User` has a `Profile` row.
    - On creation: create the profile.
    - On update: get or create to backfill missing profiles (e.g., superuser).
    """
    if created:
        profile = Profile.objects.create(user=instance)
        if not profile.safety_key:
            key = generate_safety_key()
            tries = 0
            while Profile.objects.filter(safety_key=key).exists() and tries < 5:
                key = generate_safety_key()
                tries += 1
            profile.safety_key = key
            profile.save(update_fields=["safety_key"])
    else:
        profile, _ = Profile.objects.get_or_create(user=instance)
        if not profile.safety_key:
            key = generate_safety_key()
            tries = 0
            while Profile.objects.filter(safety_key=key).exists() and tries < 5:
                key = generate_safety_key()
                tries += 1
            profile.safety_key = key
            profile.save(update_fields=["safety_key"])
