#!/usr/bin/env python
"""
Script to add sample MFA log data for testing the realtime monitoring dashboard.
"""
import os
import sys
import django
from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mysite.settings')
django.setup()

from django.contrib.auth.models import User
from mfa.models import MFALog

SAMPLE_TAG = "[SAMPLE]"

def create_sample_data():
    """Create sample MFA log entries for testing (tagged for safe cleanup)."""
    # Safety guard: don't run on production unless explicitly allowed
    if not settings.DEBUG and os.environ.get("ALLOW_SAMPLE_DATA") != "1":
        print("Refusing to run: settings.DEBUG is False. Set ALLOW_SAMPLE_DATA=1 to override (not recommended).")
        sys.exit(1)

    # Use existing superuser or create one
    try:
        user = User.objects.filter(is_superuser=True).first()
        if not user:
            user = User.objects.create_superuser(
                username='admin',
                email='admin@example.com',
                password='admin123'
            )
    except Exception as e:
        print(f"Error creating user: {e}")
        # Try to get any existing user
        user = User.objects.first()
        if not user:
            print("No users found in database")
            return
    
    # Create sample MFA log entries with various events
    sample_events = [
        {
            'event': 'email_verify_success',
            'method': 'email',
            'ip_address': '192.168.1.100',
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'details': 'Email OTP verification successful',
            'minutes_ago': 5
        },
        {
            'event': 'totp_verify_success', 
            'method': 'totp',
            'ip_address': '192.168.1.101',
            'user_agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)',
            'details': 'TOTP verification successful',
            'minutes_ago': 12
        },
        {
            'event': 'email_verify_failure',
            'method': 'email',
            'ip_address': '10.0.0.50',
            'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            'details': 'Invalid email OTP code',
            'minutes_ago': 18
        },
        {
            'event': 'login_success',
            'method': 'email',
            'ip_address': '192.168.1.100',
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'details': 'User login successful after email OTP',
            'minutes_ago': 25
        },
        {
            'event': 'backup_code_used',
            'method': 'backup_code',
            'ip_address': '172.16.0.10',
            'user_agent': 'Mozilla/5.0 (Android 11; Mobile)',
            'details': 'Backup code authentication',
            'minutes_ago': 35
        },
        {
            'event': 'totp_verify_failure',
            'method': 'totp',
            'ip_address': '203.0.113.45',
            'user_agent': 'Mozilla/5.0 (X11; Linux x86_64)',
            'details': 'Invalid TOTP code',
            'minutes_ago': 42
        },
        {
            'event': 'email_send_success',
            'method': 'email',
            'ip_address': '192.168.1.100',
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'details': 'OTP email sent successfully',
            'minutes_ago': 48
        },
        {
            'event': 'passkey_auth_success',
            'method': 'passkey',
            'ip_address': '192.168.1.102',
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'details': 'Passkey authentication successful',
            'minutes_ago': 55
        }
    ]
    
    created_logs = []
    for event_data in sample_events:
        log_time = timezone.now() - timedelta(minutes=event_data['minutes_ago'])
        
        log_entry = MFALog.objects.create(
            user=user,
            event=event_data['event'],
            method=event_data['method'],
            ip_address=event_data['ip_address'],
            user_agent=event_data['user_agent'],
            details=f"{SAMPLE_TAG} {event_data['details']}",
            created_at=log_time
        )
        created_logs.append(log_entry)
        
    print(f"Created {len(created_logs)} sample MFA log entries")
    
    print(f"All sample data created for user: {user.username}")
    print(f"Total MFA logs in database: {MFALog.objects.count()}")


def delete_sample_data():
    """Remove previously inserted sample data (tagged with SAMPLE_TAG)."""
    qs = MFALog.objects.filter(details__startswith=SAMPLE_TAG)
    count = qs.count()
    qs.delete()
    print(f"Deleted {count} tagged sample MFA log entries")

if __name__ == '__main__':
    # Usage:
    #   python add_sample_data.py         -> create sample data (guarded by DEBUG)
    #   python add_sample_data.py delete -> delete tagged sample data
    if len(sys.argv) > 1 and sys.argv[1].lower() in {"delete", "clean", "remove"}:
        delete_sample_data()
    else:
        create_sample_data()
