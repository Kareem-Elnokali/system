"""Enhanced security models for real implementation"""
from django.conf import settings
from django.db import models
from django.utils import timezone
import json


class UserSession(models.Model):
    """Enhanced session tracking with geolocation and device info"""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='user_sessions')
    session_key = models.CharField(max_length=40, unique=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    device_fingerprint = models.CharField(max_length=64, blank=True)
    location_country = models.CharField(max_length=2, blank=True)
    location_city = models.CharField(max_length=100, blank=True)
    location_lat = models.FloatField(null=True, blank=True)
    location_lng = models.FloatField(null=True, blank=True)
    is_suspicious = models.BooleanField(default=False)
    risk_score = models.IntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)
    last_activity = models.DateTimeField(default=timezone.now)
    
    class Meta:
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['is_suspicious']),
        ]
    
    def __str__(self):
        return f"UserSession({self.user}, {self.ip_address})"


class ThreatIntelligence(models.Model):
    """Threat intelligence data for IPs and domains"""
    THREAT_TYPES = [
        ('malware', 'Malware'),
        ('phishing', 'Phishing'),
        ('spam', 'Spam'),
        ('botnet', 'Botnet'),
        ('scanner', 'Scanner'),
        ('bruteforce', 'Brute Force'),
    ]
    
    ip_address = models.GenericIPAddressField(unique=True)
    threat_type = models.CharField(max_length=20, choices=THREAT_TYPES)
    threat_score = models.IntegerField(default=0)  # 0-100
    source = models.CharField(max_length=100)  # e.g., 'VirusTotal', 'AbuseIPDB'
    last_seen = models.DateTimeField()
    is_blocked = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['threat_score']),
            models.Index(fields=['is_blocked']),
        ]
    
    def __str__(self):
        return f"ThreatIntelligence({self.ip_address}, {self.threat_type})"


class UserBehavior(models.Model):
    """User behavior tracking for anomaly detection"""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='behavior_logs')
    action = models.CharField(max_length=50)  # login, logout, mfa_setup, etc.
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    location_country = models.CharField(max_length=2, blank=True)
    location_city = models.CharField(max_length=100, blank=True)
    device_fingerprint = models.CharField(max_length=64, blank=True)
    is_anomaly = models.BooleanField(default=False)
    anomaly_score = models.FloatField(default=0.0)
    anomaly_reasons = models.JSONField(default=list)
    timestamp = models.DateTimeField(default=timezone.now)
    
    class Meta:
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['is_anomaly']),
            models.Index(fields=['action']),
        ]
    
    def __str__(self):
        return f"UserBehavior({self.user}, {self.action})"


class DeviceFingerprint(models.Model):
    """Device fingerprinting data"""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='device_fingerprints')
    fingerprint_hash = models.CharField(max_length=64, unique=True)
    device_info = models.JSONField()  # Browser, OS, screen resolution, etc.
    is_trusted = models.BooleanField(default=False)
    is_blocked = models.BooleanField(default=False)
    fraud_score = models.IntegerField(default=0)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    
    class Meta:
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['fingerprint_hash']),
            models.Index(fields=['is_trusted']),
        ]
    
    def __str__(self):
        return f"DeviceFingerprint({self.user}, {self.fingerprint_hash[:8]}...)"


class SecurityIncident(models.Model):
    """Security incident tracking"""
    INCIDENT_TYPES = [
        ('suspicious_login', 'Suspicious Login'),
        ('brute_force', 'Brute Force Attack'),
        ('anomaly_detected', 'Anomaly Detected'),
        ('threat_detected', 'Threat Detected'),
        ('device_fraud', 'Device Fraud'),
        ('location_anomaly', 'Location Anomaly'),
    ]
    
    SEVERITY_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('investigating', 'Investigating'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
    ]
    
    incident_id = models.CharField(max_length=20, unique=True)
    incident_type = models.CharField(max_length=20, choices=INCIDENT_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='open')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    description = models.TextField()
    details = models.JSONField(default=dict)
    assigned_to = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_incidents')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['status', 'severity']),
            models.Index(fields=['incident_type']),
            models.Index(fields=['created_at']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.incident_id:
            from datetime import datetime
            import random
            self.incident_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"SecurityIncident({self.incident_id}, {self.incident_type})"


class SecurityNotification(models.Model):
    """Security notifications and alerts"""
    NOTIFICATION_TYPES = [
        ('security_alert', 'Security Alert'),
        ('system_notification', 'System Notification'),
        ('incident_update', 'Incident Update'),
        ('compliance_alert', 'Compliance Alert'),
    ]
    
    PRIORITY_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='security_notifications')
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    priority = models.CharField(max_length=10, choices=PRIORITY_LEVELS)
    title = models.CharField(max_length=200)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    is_dismissed = models.BooleanField(default=False)
    action_required = models.BooleanField(default=False)
    action_url = models.URLField(blank=True)
    metadata = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now)
    read_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['user', 'is_read']),
            models.Index(fields=['priority']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"SecurityNotification({self.user}, {self.title})"


class APIUsage(models.Model):
    """API usage tracking"""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    endpoint = models.CharField(max_length=200)
    method = models.CharField(max_length=10)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    status_code = models.IntegerField()
    response_time = models.FloatField()  # in milliseconds
    request_size = models.IntegerField(default=0)
    response_size = models.IntegerField(default=0)
    timestamp = models.DateTimeField(default=timezone.now)
    
    class Meta:
        indexes = [
            models.Index(fields=['endpoint', 'timestamp']),
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['status_code']),
        ]
    
    def __str__(self):
        return f"APIUsage({self.endpoint}, {self.method})"


class ComplianceReport(models.Model):
    """Compliance reporting data"""
    REPORT_TYPES = [
        ('gdpr', 'GDPR Compliance'),
        ('hipaa', 'HIPAA Compliance'),
        ('sox', 'SOX Compliance'),
        ('pci_dss', 'PCI DSS Compliance'),
        ('iso27001', 'ISO 27001 Compliance'),
    ]
    
    report_type = models.CharField(max_length=20, choices=REPORT_TYPES)
    report_period_start = models.DateTimeField()
    report_period_end = models.DateTimeField()
    compliance_score = models.FloatField()  # 0-100
    findings = models.JSONField(default=list)
    recommendations = models.JSONField(default=list)
    generated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    generated_at = models.DateTimeField(default=timezone.now)
    file_path = models.CharField(max_length=500, blank=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['report_type', 'generated_at']),
            models.Index(fields=['compliance_score']),
        ]
    
    def __str__(self):
        return f"ComplianceReport({self.report_type}, {self.compliance_score}%)"
