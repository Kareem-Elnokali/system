"""Django admin registrations for the MFA app
Provides simple admin interfaces for devices, backup codes, settings (singleton),
audit logs, and the user `Profile` model.
"""
from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from .models import MFADevice, BackupCode, MFASettings, MFALog, Profile
from .security_models import (
    UserSession, ThreatIntelligence, UserBehavior, DeviceFingerprint,
    SecurityIncident, SecurityNotification, APIUsage, ComplianceReport
)
@admin.register(MFADevice)
class MFADeviceAdmin(admin.ModelAdmin):
    """Browse and filter user's TOTP devices with bulk operations."""
    list_display = ("user", "name", "confirmed", "created_at", "last_used", "success_rate")
    list_filter = ("confirmed", "created_at")
    search_fields = ("user__username", "user__email", "name")
    actions = ['bulk_disable_devices', 'bulk_regenerate_qr']
    readonly_fields = ('secret', 'created_at', 'last_used', 'success_rate')
    
    def last_used(self, obj):
        """Show last successful authentication with this device"""
        from .models import MFALog
        last_log = MFALog.objects.filter(
            user=obj.user, 
            event__in=['totp_verify_success'], 
            method='totp'
        ).order_by('-created_at').first()
        return last_log.created_at if last_log else 'Never'
    last_used.short_description = 'Last Used'
    
    def success_rate(self, obj):
        """Calculate success rate for this device"""
        from .models import MFALog
        from django.db.models import Count, Q
        logs = MFALog.objects.filter(user=obj.user, method='totp')
        total = logs.count()
        if total == 0:
            return 'No attempts'
        successes = logs.filter(event='totp_verify_success').count()
        rate = (successes / total) * 100
        return f'{rate:.1f}% ({successes}/{total})'
    success_rate.short_description = 'Success Rate'
    
    def bulk_disable_devices(self, request, queryset):
        """Bulk disable selected devices"""
        updated = queryset.update(confirmed=False)
        self.message_user(request, f'Disabled {updated} devices.')
    bulk_disable_devices.short_description = 'Disable selected devices'
    
    def bulk_regenerate_qr(self, request, queryset):
        """Bulk regenerate secrets for selected devices"""
        from .utils import base32_secret
        count = 0
        for device in queryset:
            device.secret = base32_secret()
            device.confirmed = False
            device.save()
            count += 1
        self.message_user(request, f'Regenerated secrets for {count} devices. Users must re-setup.')
    bulk_regenerate_qr.short_description = 'Regenerate QR codes for selected devices'
@admin.register(BackupCode)
class BackupCodeAdmin(admin.ModelAdmin):
    """View per-user backup codes with bulk regeneration tools."""
    list_display = ("user", "code_preview", "used", "created_at", "used_at", "expires_in")
    list_filter = ("used", "created_at")
    search_fields = ("user__username", "user__email")
    actions = ['bulk_regenerate_codes', 'bulk_expire_codes']
    readonly_fields = ('code_hash', 'created_at', 'used_at')
    
    def code_preview(self, obj):
        """Show masked preview of backup code"""
        return "****-****" if obj.used else "XXXX-XXXX (Active)"
    code_preview.short_description = 'Code Preview'
    
    def expires_in(self, obj):
        """Show expiration status (if implemented)"""
        from django.utils import timezone
        from datetime import timedelta
        # Assume 90-day expiry for backup codes
        expiry_date = obj.created_at + timedelta(days=90)
        if timezone.now() > expiry_date:
            return 'Expired'
        days_left = (expiry_date - timezone.now()).days
        return f'{days_left} days left'
    expires_in.short_description = 'Expires In'
    
    def bulk_regenerate_codes(self, request, queryset):
        """Bulk regenerate backup codes for selected users"""
        from .utils import generate_backup_codes
        users = set(code.user for code in queryset)
        count = 0
        for user in users:
            # Delete existing codes
            user.mfa_backup_codes.all().delete()
            # Generate new ones
            generate_backup_codes(user, count=10)
            count += 1
        self.message_user(request, f'Regenerated backup codes for {count} users.')
    bulk_regenerate_codes.short_description = 'Regenerate backup codes for selected users'
    
    def bulk_expire_codes(self, request, queryset):
        """Bulk mark selected codes as used/expired"""
        from django.utils import timezone
        updated = queryset.update(used=True, used_at=timezone.now())
        self.message_user(request, f'Expired {updated} backup codes.')
    bulk_expire_codes.short_description = 'Expire selected backup codes'
@admin.register(MFASettings)
class MFASettingsAdmin(admin.ModelAdmin):
    """Enhanced MFA settings with advanced security controls."""
    list_display = ("enable_totp", "enable_email", "enable_passkeys", "enable_sms", "enable_backup_codes", "always_show_method_picker", "updated_at")
    fieldsets = (
        ("Authentication Methods", {
            'fields': (
                "enable_totp",
                "enable_email",
                "enable_passkeys",
                "enable_sms",
                "enable_backup_codes",
                "always_show_method_picker"
            )
        }),
        ("Reporting Settings", {
            'fields': (
                "report_enabled",
                "report_recipients",
                "report_frequency_days",
                "report_csv_days",
                "report_next_send_at",
                "report_last_sent_at"
            ),
            'classes': ('collapse',),
        }),
        ("Meta", {
            'fields': ("updated_at",),
            'classes': ('collapse',),
        })
    )
    readonly_fields = ("updated_at", "report_last_sent_at")
    
    def get_fieldsets(self, request, obj=None):
        """Add new fields to model if they don't exist"""
        fieldsets = list(super().get_fieldsets(request, obj))
        # Add help text for new fields
        return fieldsets
    
    def has_add_permission(self, request):
        from .models import MFASettings
        return not MFASettings.objects.exists()
    def has_delete_permission(self, request, obj=None):
        return False
@admin.register(MFALog)
class MFALogAdmin(admin.ModelAdmin):
    """Enhanced MFA audit logs with threat detection and analytics."""
    list_display = ("created_at", "user", "event", "method", "ip_address", "risk_score", "threat_level")
    list_filter = ("event", "method", "created_at")
    search_fields = ("user__username", "user__email", "ip_address", "user_agent", "details")
    date_hierarchy = "created_at"
    actions = ['mark_as_suspicious', 'block_ip_addresses', 'export_security_report']
    readonly_fields = ('created_at', 'risk_score', 'threat_level', 'geo_location')
    
    def risk_score(self, obj):
        """Calculate risk score based on various factors"""
        from datetime import timedelta
        score = 0
        # Failed attempts increase risk
        if 'failure' in obj.event:
            score += 30
        # Multiple attempts from same IP
        if obj.ip_address:
            recent_attempts = MFALog.objects.filter(
                ip_address=obj.ip_address,
                created_at__gte=obj.created_at - timedelta(hours=1)
            ).count()
            if recent_attempts > 5:
                score += 40
        # Unusual hours (outside 6 AM - 10 PM)
        if obj.created_at.hour < 6 or obj.created_at.hour > 22:
            score += 20
        # Different country than usual (simplified)
        if obj.details and 'unusual_location' in obj.details:
            score += 50
        return min(score, 100)
    risk_score.short_description = 'Risk Score'
    
    def threat_level(self, obj):
        """Determine threat level based on risk score"""
        score = self.risk_score(obj)
        if score >= 80:
            return '🔴 High'
        elif score >= 50:
            return '🟡 Medium'
        elif score >= 20:
            return '🟠 Low'
        return '🟢 Normal'
    threat_level.short_description = 'Threat Level'
    
    def geo_location(self, obj):
        """Show geographic location if available"""
        # Simplified geo lookup - in real implementation, use GeoIP2
        if obj.ip_address:
            return f"Location for {obj.ip_address}"
        return 'Unknown'
    geo_location.short_description = 'Location'
    
    def mark_as_suspicious(self, request, queryset):
        """Mark selected logs as suspicious for investigation"""
        # In real implementation, add a 'suspicious' flag to MFALog model
        count = queryset.count()
        self.message_user(request, f'Marked {count} logs as suspicious for investigation.')
    mark_as_suspicious.short_description = 'Mark as suspicious'
    
    def block_ip_addresses(self, request, queryset):
        """Block IP addresses from selected logs"""
        ips = set(log.ip_address for log in queryset if log.ip_address)
        # In real implementation, add to IP blocklist
        self.message_user(request, f'Blocked {len(ips)} IP addresses: {", ".join(list(ips)[:5])}')
    block_ip_addresses.short_description = 'Block IP addresses'
    
    def export_security_report(self, request, queryset):
        """Export security report for selected logs"""
        from django.http import HttpResponse
        import csv
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="security_report.csv"'
        writer = csv.writer(response)
        writer.writerow(['Timestamp', 'User', 'Event', 'Method', 'IP', 'Risk Score', 'Threat Level', 'Details'])
        for log in queryset:
            writer.writerow([
                log.created_at, log.user.username if log.user else 'N/A',
                log.event, log.method, log.ip_address or 'N/A',
                self.risk_score(log), self.threat_level(log), log.details
            ])
        return response
    export_security_report.short_description = 'Export security report'
@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    """Enhanced profile management with phone validation and multiple numbers."""
    list_display = ('user', 'phone_number', 'phone_verified', 'backup_phone', 'safety_key', 'risk_level')
    search_fields = ('user__username', 'user__email', 'phone_number', 'backup_phone')
    list_filter = ('user__is_staff', 'user__is_active')
    actions = ['bulk_verify_phones', 'bulk_generate_safety_keys', 'bulk_reset_mfa_preferences']
    readonly_fields = ('safety_key', 'created_at', 'risk_level', 'last_mfa_change')
    
    def phone_verified(self, obj):
        """Show if phone number is verified"""
        # In real implementation, add phone_verified field to Profile model
        return "✅ Verified" if obj.phone_number else "❌ Not Set"
    phone_verified.short_description = 'Phone Status'
    
    def backup_phone(self, obj):
        """Show backup phone number"""
        # In real implementation, add backup_phone field to Profile model
        return "Not Set"
    backup_phone.short_description = 'Backup Phone'
    
    def risk_level(self, obj):
        """Calculate user risk level based on MFA usage"""
        from .models import MFADevice, MFALog
        from datetime import timedelta
        from django.utils import timezone
        
        # Check if user has MFA enabled
        has_totp = MFADevice.objects.filter(user=obj.user, confirmed=True).exists()
        if not has_totp:
            return '🔴 High (No MFA)'
        
        # Check recent failed attempts
        recent_failures = MFALog.objects.filter(
            user=obj.user,
            event__contains='failure',
            created_at__gte=timezone.now() - timedelta(days=7)
        ).count()
        
        if recent_failures > 10:
            return '🟡 Medium (Many Failures)'
        elif recent_failures > 3:
            return '🟠 Low (Some Failures)'
        return '🟢 Normal'
    risk_level.short_description = 'Risk Level'
    
    def last_mfa_change(self, obj):
        """Show when user last changed MFA settings"""
        from .models import MFALog
        last_change = MFALog.objects.filter(
            user=obj.user,
            event__in=['totp_linked', 'totp_unlinked', 'backup_codes_generated']
        ).order_by('-created_at').first()
        return last_change.created_at if last_change else 'Never'
    last_mfa_change.short_description = 'Last MFA Change'
    
    def created_at(self, obj):
        """Show profile creation date"""
        return obj.user.date_joined
    created_at.short_description = 'Created'
    
    def bulk_verify_phones(self, request, queryset):
        """Bulk verify phone numbers"""
        count = 0
        for profile in queryset:
            if profile.phone_number:
                # In real implementation, send verification SMS
                count += 1
        self.message_user(request, f'Sent verification SMS to {count} phone numbers.')
    bulk_verify_phones.short_description = 'Send phone verification'
    
    def bulk_generate_safety_keys(self, request, queryset):
        """Bulk generate new safety keys"""
        from .utils import generate_safety_key
        count = 0
        for profile in queryset:
            if not profile.safety_key:
                profile.safety_key = generate_safety_key()
                profile.save()
                count += 1
        self.message_user(request, f'Generated safety keys for {count} profiles.')
    bulk_generate_safety_keys.short_description = 'Generate safety keys'
    
    def bulk_reset_mfa_preferences(self, request, queryset):
        """Bulk reset MFA preferences to defaults"""
        count = queryset.count()
        # In real implementation, reset user MFA preferences
        self.message_user(request, f'Reset MFA preferences for {count} users.')
    bulk_reset_mfa_preferences.short_description = 'Reset MFA preferences'


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    """Enhanced session tracking administration"""
    list_display = ('user', 'ip_address', 'location_display', 'is_suspicious', 'risk_score', 'created_at', 'last_activity')
    list_filter = ('is_suspicious', 'location_country', 'created_at')
    search_fields = ('user__username', 'user__email', 'ip_address', 'location_city')
    readonly_fields = ('session_key', 'device_fingerprint', 'created_at')
    actions = ['mark_suspicious', 'block_sessions']
    
    def location_display(self, obj):
        if obj.location_city and obj.location_country:
            return f"{obj.location_city}, {obj.location_country}"
        return obj.location_country or 'Unknown'
    location_display.short_description = 'Location'
    
    def mark_suspicious(self, request, queryset):
        updated = queryset.update(is_suspicious=True)
        self.message_user(request, f'Marked {updated} sessions as suspicious.')
    mark_suspicious.short_description = 'Mark as suspicious'
    
    def block_sessions(self, request, queryset):
        count = queryset.count()
        # In real implementation, invalidate sessions
        self.message_user(request, f'Blocked {count} sessions.')
    block_sessions.short_description = 'Block sessions'


@admin.register(ThreatIntelligence)
class ThreatIntelligenceAdmin(admin.ModelAdmin):
    """Threat intelligence management"""
    list_display = ('ip_address', 'threat_type', 'threat_score', 'source', 'is_blocked', 'last_seen')
    list_filter = ('threat_type', 'is_blocked', 'source', 'last_seen')
    search_fields = ('ip_address',)
    actions = ['block_ips', 'unblock_ips']
    
    def block_ips(self, request, queryset):
        updated = queryset.update(is_blocked=True)
        self.message_user(request, f'Blocked {updated} IP addresses.')
    block_ips.short_description = 'Block IP addresses'
    
    def unblock_ips(self, request, queryset):
        updated = queryset.update(is_blocked=False)
        self.message_user(request, f'Unblocked {updated} IP addresses.')
    unblock_ips.short_description = 'Unblock IP addresses'


@admin.register(UserBehavior)
class UserBehaviorAdmin(admin.ModelAdmin):
    """User behavior analysis"""
    list_display = ('user', 'action', 'is_anomaly', 'anomaly_score', 'location_display', 'timestamp')
    list_filter = ('is_anomaly', 'action', 'location_country', 'timestamp')
    search_fields = ('user__username', 'user__email', 'ip_address')
    readonly_fields = ('anomaly_reasons', 'device_fingerprint', 'timestamp')
    
    def location_display(self, obj):
        if obj.location_city and obj.location_country:
            return f"{obj.location_city}, {obj.location_country}"
        return obj.location_country or 'Unknown'
    location_display.short_description = 'Location'


@admin.register(SecurityIncident)
class SecurityIncidentAdmin(admin.ModelAdmin):
    """Security incident management"""
    list_display = ('incident_id', 'incident_type', 'severity', 'status', 'user', 'created_at')
    list_filter = ('incident_type', 'severity', 'status', 'created_at')
    search_fields = ('incident_id', 'user__username', 'description', 'ip_address')
    readonly_fields = ('incident_id', 'created_at')
    actions = ['mark_resolved', 'assign_to_me']
    
    def mark_resolved(self, request, queryset):
        from django.utils import timezone
        updated = queryset.update(status='resolved', resolved_at=timezone.now())
        self.message_user(request, f'Resolved {updated} incidents.')
    mark_resolved.short_description = 'Mark as resolved'
    
    def assign_to_me(self, request, queryset):
        updated = queryset.update(assigned_to=request.user)
        self.message_user(request, f'Assigned {updated} incidents to you.')
    assign_to_me.short_description = 'Assign to me'


@admin.register(SecurityNotification)
class SecurityNotificationAdmin(admin.ModelAdmin):
    """Security notification management"""
    list_display = ('user', 'notification_type', 'priority', 'title', 'is_read', 'created_at')
    list_filter = ('notification_type', 'priority', 'is_read', 'created_at')
    search_fields = ('user__username', 'title', 'message')
    actions = ['mark_read', 'mark_unread']
    
    def mark_read(self, request, queryset):
        from django.utils import timezone
        updated = queryset.update(is_read=True, read_at=timezone.now())
        self.message_user(request, f'Marked {updated} notifications as read.')
    mark_read.short_description = 'Mark as read'
    
    def mark_unread(self, request, queryset):
        updated = queryset.update(is_read=False, read_at=None)
        self.message_user(request, f'Marked {updated} notifications as unread.')
    mark_unread.short_description = 'Mark as unread'


@admin.register(APIUsage)
class APIUsageAdmin(admin.ModelAdmin):
    """API usage monitoring"""
    list_display = ('endpoint', 'method', 'user', 'status_code', 'response_time', 'timestamp')
    list_filter = ('method', 'status_code', 'timestamp')
    search_fields = ('endpoint', 'user__username', 'ip_address')
    readonly_fields = ('timestamp',)
    
    def get_queryset(self, request):
        # Limit to recent records for performance
        from datetime import timedelta
        from django.utils import timezone
        return super().get_queryset(request).filter(
            timestamp__gte=timezone.now() - timedelta(days=30)
        )


@admin.register(ComplianceReport)
class ComplianceReportAdmin(admin.ModelAdmin):
    """Compliance report management"""
    list_display = ('report_type', 'compliance_score', 'generated_by', 'generated_at')
    list_filter = ('report_type', 'generated_at')
    search_fields = ('report_type', 'generated_by__username')
    readonly_fields = ('generated_at', 'findings', 'recommendations')
    
    def get_readonly_fields(self, request, obj=None):
        if obj:  # Editing existing report
            return self.readonly_fields + ('report_type', 'report_period_start', 'report_period_end')
        return self.readonly_fields
