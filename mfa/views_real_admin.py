# Real Admin Dashboard Views with Database Integration
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.db.models import Count, Avg, Q, Sum
from django.utils import timezone
from datetime import timedelta
from .decorators import admin_groups_required, admin_mfa_required
from .security_models import (
    UserSession, ThreatIntelligence, UserBehavior, DeviceFingerprint,
    SecurityIncident, SecurityNotification, APIUsage, ComplianceReport
)
from django.contrib.auth.models import Group, Permission
from django.contrib.auth import get_user_model
from .models import MFALog

@require_http_methods(["GET"])
@admin_groups_required('Security Admin', 'Analyst', 'Support')
def admin_session_management(request):
    """Session management dashboard with real data"""
    # Get active sessions from last 24 hours
    active_sessions = UserSession.objects.filter(
        last_activity__gte=timezone.now() - timedelta(hours=24)
    ).select_related('user').order_by('-last_activity')[:10]
    
    # Count suspicious sessions
    suspicious_sessions = UserSession.objects.filter(is_suspicious=True).count()
    
    # Geographic distribution
    geo_distribution = dict(
        UserSession.objects.filter(
            created_at__gte=timezone.now() - timedelta(days=7)
        ).values('location_country').annotate(
            count=Count('id')
        ).values_list('location_country', 'count')[:5]
    )
    
    # Session analytics
    total_sessions = UserSession.objects.count()
    new_sessions = UserSession.objects.filter(
        created_at__gte=timezone.now() - timedelta(days=1)
    ).count()
    
    context = {
        'active_sessions': active_sessions,
        'suspicious_sessions': suspicious_sessions,
        'geo_distribution': geo_distribution,
        'session_analytics': {'new': new_sessions, 'returning': total_sessions - new_sessions}
    }
    return render(request, 'admin/session_management.html', context)

@require_http_methods(["GET"])
@admin_groups_required('Security Admin', 'Analyst')
def admin_geolocation_tracking(request):
    """Geolocation tracking dashboard with real data"""
    # Count unique trusted locations (non-suspicious)
    trusted_locations = UserSession.objects.filter(
        is_suspicious=False
    ).values('location_city', 'location_country').distinct().count()
    
    # New locations in last 24 hours
    new_locations = UserSession.objects.filter(
        created_at__gte=timezone.now() - timedelta(hours=24)
    ).values('location_city', 'location_country').distinct().count()
    
    # Suspicious locations
    suspicious_locations = UserSession.objects.filter(
        is_suspicious=True
    ).values('location_city', 'location_country').distinct().count()
    
    # Location analytics
    countries = UserSession.objects.values('location_country').distinct().count()
    cities = UserSession.objects.values('location_city').distinct().count()
    
    context = {
        'trusted_locations': trusted_locations,
        'new_locations': new_locations,
        'suspicious_locations': suspicious_locations,
        'location_analytics': {'countries': countries, 'cities': cities}
    }
    return render(request, 'admin/geolocation_tracking.html', context)

@require_http_methods(["GET"])
@admin_groups_required('Security Admin', 'Analyst')
def admin_threat_intelligence(request):
    """Threat intelligence dashboard with real data"""
    # Active threats in last 24 hours
    active_threats = ThreatIntelligence.objects.filter(
        last_seen__gte=timezone.now() - timedelta(hours=24)
    ).count()
    
    # Blocked IPs
    blocked_ips = ThreatIntelligence.objects.filter(is_blocked=True).count()
    
    # Average threat score
    threat_score = ThreatIntelligence.objects.aggregate(
        avg_score=Avg('threat_score')
    )['avg_score'] or 0
    
    # Recent threats
    recent_threats = ThreatIntelligence.objects.filter(
        last_seen__gte=timezone.now() - timedelta(days=7)
    ).order_by('-last_seen')[:10]
    
    # Threat distribution by type
    threat_distribution = dict(
        ThreatIntelligence.objects.values('threat_type').annotate(
            count=Count('id')
        ).values_list('threat_type', 'count')
    )
    
    context = {
        'active_threats': active_threats,
        'blocked_ips': blocked_ips,
        'threat_score': round(threat_score, 1),
        'recent_threats': recent_threats,
        'threat_distribution': threat_distribution
    }
    return render(request, 'admin/threat_intelligence.html', context)

@require_http_methods(["GET"])
@admin_groups_required('Security Admin', 'Analyst')
def admin_user_behavior_analytics(request):
    """User behavior analytics dashboard with real data"""
    # Behavior patterns count
    behavior_patterns = UserBehavior.objects.values('action').distinct().count()
    
    # Anomalies detected
    anomalies_detected = UserBehavior.objects.filter(is_anomaly=True).count()
    
    # High risk users
    risk_users = UserBehavior.objects.filter(
        is_anomaly=True,
        anomaly_score__gte=0.8
    ).values('user').distinct().count()
    
    # Recent anomalies
    recent_anomalies = UserBehavior.objects.filter(
        is_anomaly=True,
        timestamp__gte=timezone.now() - timedelta(days=7)
    ).select_related('user').order_by('-timestamp')[:10]
    
    # Behavior distribution
    behavior_distribution = dict(
        UserBehavior.objects.values('action').annotate(
            count=Count('id')
        ).values_list('action', 'count')[:10]
    )
    
    context = {
        'behavior_patterns': behavior_patterns,
        'anomalies_detected': anomalies_detected,
        'risk_users': risk_users,
        'recent_anomalies': recent_anomalies,
        'behavior_distribution': behavior_distribution
    }
    return render(request, 'admin/user_behavior_analytics.html', context)

@require_http_methods(["GET"])
@admin_groups_required('Security Admin', 'Analyst')
def admin_device_fingerprinting(request):
    """Device fingerprinting dashboard with real data"""
    # Unique devices
    unique_devices = DeviceFingerprint.objects.values('fingerprint_hash').distinct().count()
    
    # Fraud attempts (suspicious devices)
    fraud_attempts = DeviceFingerprint.objects.filter(is_trusted=False).count()
    
    # Bot detections (could be based on device characteristics)
    bot_detections = DeviceFingerprint.objects.filter(
        device_info__icontains='bot'
    ).count()
    
    # Recent devices
    recent_devices = DeviceFingerprint.objects.select_related('user').order_by('-last_seen')[:10]
    
    # Compute trust score (percentage of trusted devices)
    total_devices = DeviceFingerprint.objects.count()
    trusted_devices = DeviceFingerprint.objects.filter(is_trusted=True).count()
    trust_score = round((trusted_devices / total_devices) * 100, 1) if total_devices else 100
    
    # Map recent devices into a template-friendly structure
    fingerprints = []
    for dev in recent_devices:
        info = dev.device_info or {}
        browser = info.get('browser') or info.get('user_agent') or '-'
        platform = info.get('platform') or info.get('os') or '-'
        risk_score = int(dev.fraud_score or 0)
        if risk_score >= 70:
            risk_level = 'high'
        elif risk_score >= 40:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        fingerprints.append({
            'device_id': dev.fingerprint_hash,
            'user_username': getattr(dev.user, 'username', None) or '-',
            'user_email': getattr(dev.user, 'email', None) or '-',
            'browser': browser,
            'os': platform,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'last_seen': dev.last_seen,
        })
    
    # Recent detections from SecurityIncident
    recent_incidents = SecurityIncident.objects.order_by('-created_at')[:5]
    icon_map = {
        'suspicious_login': 'exclamation-triangle',
        'brute_force': 'user-shield',
        'anomaly_detected': 'wave-square',
        'threat_detected': 'radiation',
        'device_fraud': 'mobile-alt',
        'location_anomaly': 'globe',
    }
    recent_detections = []
    for inc in recent_incidents:
        recent_detections.append({
            'title': inc.get_incident_type_display() if hasattr(inc, 'get_incident_type_display') else inc.incident_type,
            'subtitle': f"User: {getattr(inc.user, 'username', 'N/A')}" if inc.user_id else (f"IP: {inc.ip_address}" if inc.ip_address else ''),
            'when': inc.created_at,
            'severity': inc.severity,
            'icon': icon_map.get(inc.incident_type, 'exclamation-triangle'),
        })
    
    # Device type distribution
    device_distribution = dict(
        DeviceFingerprint.objects.extra(
            select={'device_type': "JSON_EXTRACT(device_info, '$.platform')"}
        ).values('device_type').annotate(
            count=Count('id')
        ).values_list('device_type', 'count')[:5]
    )
    
    context = {
        'unique_devices': unique_devices,
        'fraud_attempts': fraud_attempts,
        'bot_detections': bot_detections,
        'recent_devices': recent_devices,
        'fingerprints': fingerprints,
        'recent_detections': recent_detections,
        'trust_score': trust_score,
        'device_distribution': device_distribution
    }
    return render(request, 'admin/device_fingerprinting.html', context)

@require_http_methods(["GET"])
@admin_groups_required('Security Admin', 'Analyst')
def admin_incident_response(request):
    """Incident response dashboard with real data"""
    # Open incidents
    open_incidents = SecurityIncident.objects.filter(status='open').count()
    
    # Resolved incidents
    resolved_incidents = SecurityIncident.objects.filter(status='resolved').count()
    
    # Average response time
    resolved_with_time = SecurityIncident.objects.filter(
        status='resolved',
        resolved_at__isnull=False
    )
    
    if resolved_with_time.exists():
        avg_seconds = resolved_with_time.extra(
            select={'response_time': 'TIMESTAMPDIFF(SECOND, created_at, resolved_at)'}
        ).aggregate(avg_time=Avg('response_time'))['avg_time'] or 0
        avg_response_time = f"{int(avg_seconds // 60)} minutes"
    else:
        avg_response_time = "N/A"
    
    # Recent incidents
    recent_incidents = SecurityIncident.objects.select_related('user').order_by('-created_at')[:10]
    
    # Incident distribution by type
    incident_distribution = dict(
        SecurityIncident.objects.values('incident_type').annotate(
            count=Count('id')
        ).values_list('incident_type', 'count')
    )
    
    context = {
        'open_incidents': open_incidents,
        'resolved_incidents': resolved_incidents,
        'avg_response_time': avg_response_time,
        'recent_incidents': recent_incidents,
        'incident_distribution': incident_distribution
    }
    return render(request, 'admin/incident_response.html', context)

@require_http_methods(["GET"])
@admin_groups_required('Security Admin', 'Support', 'Analyst')
def admin_notification_center(request):
    """Notification center dashboard with real data"""
    # Unread notifications
    unread_notifications = SecurityNotification.objects.filter(is_read=False).count()
    
    # Critical alerts
    critical_alerts = SecurityNotification.objects.filter(
        priority='critical',
        is_read=False
    ).count()
    
    # Total notifications
    total_notifications = SecurityNotification.objects.count()
    
    # Recent notifications
    recent_notifications = SecurityNotification.objects.select_related('user').order_by('-created_at')[:10]
    
    # Notification distribution by type
    notification_distribution = dict(
        SecurityNotification.objects.values('notification_type').annotate(
            count=Count('id')
        ).values_list('notification_type', 'count')
    )
    
    context = {
        'unread_notifications': unread_notifications,
        'critical_alerts': critical_alerts,
        'total_notifications': total_notifications,
        'recent_notifications': recent_notifications,
        'notification_distribution': notification_distribution
    }
    return render(request, 'admin/notification_center.html', context)

@require_http_methods(["GET"])
@admin_groups_required('Security Admin')
def admin_api_management(request):
    """API management dashboard with real data"""
    # API calls in last 24 hours
    api_calls_24h = APIUsage.objects.filter(
        timestamp__gte=timezone.now() - timedelta(hours=24)
    ).count()
    
    # API health (success rate)
    total_calls = APIUsage.objects.filter(
        timestamp__gte=timezone.now() - timedelta(hours=24)
    ).count()
    successful_calls = APIUsage.objects.filter(
        timestamp__gte=timezone.now() - timedelta(hours=24),
        status_code__lt=400
    ).count()
    api_health = (successful_calls / total_calls * 100) if total_calls > 0 else 100
    
    # Average response time
    avg_response_time = APIUsage.objects.filter(
        timestamp__gte=timezone.now() - timedelta(hours=24)
    ).aggregate(avg_time=Avg('response_time'))['avg_time'] or 0
    
    # Top endpoints
    top_endpoints = APIUsage.objects.filter(
        timestamp__gte=timezone.now() - timedelta(days=7)
    ).values('endpoint').annotate(
        count=Count('id')
    ).order_by('-count')[:5]
    
    # Error distribution
    error_distribution = dict(
        APIUsage.objects.filter(
            timestamp__gte=timezone.now() - timedelta(days=7),
            status_code__gte=400
        ).values('status_code').annotate(
            count=Count('id')
        ).values_list('status_code', 'count')
    )
    
    context = {
        'api_calls_24h': api_calls_24h,
        'active_webhooks': 0,  # Would need webhook tracking
        'api_health': round(api_health, 1),
        'avg_response_time': round(avg_response_time, 2),
        'top_endpoints': top_endpoints,
        'error_distribution': error_distribution
    }
    return render(request, 'admin/api_management.html', context)

@require_http_methods(["GET"])
@admin_groups_required('Security Admin', 'Compliance')
def admin_enterprise_reporting(request):
    """Enterprise reporting dashboard with real data"""
    # Reports generated
    reports_generated = ComplianceReport.objects.count()
    
    # Recent reports
    recent_reports = ComplianceReport.objects.order_by('-generated_at')[:10]
    
    # Average compliance score
    compliance_score = ComplianceReport.objects.aggregate(
        avg_score=Avg('compliance_score')
    )['avg_score'] or 0
    
    # Reports by type
    reports_by_type = dict(
        ComplianceReport.objects.values('report_type').annotate(
            count=Count('id')
        ).values_list('report_type', 'count')
    )
    
    # Monthly report trend
    monthly_reports = ComplianceReport.objects.filter(
        generated_at__gte=timezone.now() - timedelta(days=30)
    ).count()
    
    # Compliance KPIs (merged from deprecated admin_compliance_report)
    User = get_user_model()
    total_users = User.objects.count()
    staff_users = User.objects.filter(is_staff=True).count()
    admin_users = User.objects.filter(is_superuser=True).count()
    staff_with_mfa = User.objects.filter(is_staff=True, mfa_devices__confirmed=True).distinct().count()
    admin_with_mfa = User.objects.filter(is_superuser=True, mfa_devices__confirmed=True).distinct().count()
    recent_password_resets = MFALog.objects.filter(
        event='password_reset_requested',
        created_at__gte=timezone.now() - timedelta(days=30)
    ).count()
    failed_access_attempts = MFALog.objects.filter(
        event__contains='failure',
        created_at__gte=timezone.now() - timedelta(days=30)
    ).count()
    audit_coverage = {
        'login_attempts': MFALog.objects.filter(
            event__in=['totp_verify_success', 'totp_verify_failure', 'email_verify_success', 'email_verify_failure'],
            created_at__gte=timezone.now() - timedelta(days=30)
        ).count(),
        'mfa_changes': MFALog.objects.filter(
            event__in=['totp_linked', 'totp_unlinked', 'backup_codes_generated'],
            created_at__gte=timezone.now() - timedelta(days=30)
        ).count(),
        'admin_actions': MFALog.objects.filter(
            event__contains='admin_',
            created_at__gte=timezone.now() - timedelta(days=30)
        ).count(),
    }
    staff_mfa_compliance = (staff_with_mfa / staff_users * 100) if staff_users > 0 else 100
    admin_mfa_compliance = (admin_with_mfa / admin_users * 100) if admin_users > 0 else 100
    overall_mfa_compliance = (
        (total_users - User.objects.filter(~Q(mfa_devices__confirmed=True)).distinct().count()) / total_users * 100
        if total_users > 0 else 0
    )
    # Simple recommendations
    recommendations = []
    if staff_mfa_compliance < 100:
        recommendations.append("Enforce MFA for all staff members")
    if admin_mfa_compliance < 100:
        recommendations.append("Require MFA for all administrator accounts")
    if failed_access_attempts > 100:
        recommendations.append("Investigate elevated failed access attempts in the last 30 days")
    if recent_password_resets > 50:
        recommendations.append("Monitor password reset frequency for potential security issues")
    
    context = {
        'reports_generated': reports_generated,
        'scheduled_reports': 0,  # Would need scheduling system
        'compliance_score': round(compliance_score, 1),
        'recent_reports': recent_reports,
        'reports_by_type': reports_by_type,
        'monthly_reports': monthly_reports,
        # Compliance KPIs
        'total_users': total_users,
        'staff_users': staff_users,
        'admin_users': admin_users,
        'staff_mfa_compliance': round(staff_mfa_compliance, 1),
        'admin_mfa_compliance': round(admin_mfa_compliance, 1),
        'overall_mfa_compliance': round(overall_mfa_compliance, 1),
        'recent_password_resets': recent_password_resets,
        'failed_access_attempts': failed_access_attempts,
        'audit_coverage': audit_coverage,
        'recommendations': recommendations,
    }
    return render(request, 'admin/enterprise_reporting.html', context)

@require_http_methods(["GET"])
@admin_groups_required('Security Admin', 'Analyst')
def admin_ml_risk_engine(request):
    """Deprecated: consolidated under admin_predictive_analytics. This view is no longer routed."""
    # Kept intentionally removed to avoid dead code; URL now points to admin_predictive_analytics.
    from django.http import HttpResponsePermanentRedirect
    from django.urls import reverse
    return HttpResponsePermanentRedirect(reverse('mfa:admin_predictive_analytics'))

@require_http_methods(["GET"])
@admin_groups_required('Security Admin', 'Compliance')
def admin_forensics_audit(request):
    """Forensics and audit dashboard with real data"""
    from .models import MFALog
    
    # Audit entries (MFA logs + Security incidents)
    audit_entries = MFALog.objects.count() + SecurityIncident.objects.count()
    
    # Forensic cases (high severity incidents)
    forensic_cases = SecurityIncident.objects.filter(severity='high').count()
    
    # Compliance checks (reports generated)
    compliance_checks = ComplianceReport.objects.count()
    
    # Recent audit activities
    recent_logs = MFALog.objects.order_by('-created_at')[:5]
    recent_incidents = SecurityIncident.objects.order_by('-created_at')[:5]
    
    # Audit activity distribution
    activity_distribution = {
        'mfa_events': MFALog.objects.filter(created_at__gte=timezone.now() - timedelta(days=7)).count(),
        'security_incidents': SecurityIncident.objects.filter(created_at__gte=timezone.now() - timedelta(days=7)).count(),
        'compliance_reports': ComplianceReport.objects.filter(generated_at__gte=timezone.now() - timedelta(days=7)).count(),
    }
    
    context = {
        'audit_entries': audit_entries,
        'forensic_cases': forensic_cases,
        'compliance_checks': compliance_checks,
        'recent_logs': recent_logs,
        'recent_incidents': recent_incidents,
        'activity_distribution': activity_distribution
    }
    return render(request, 'admin/forensics_audit.html', context)


@require_http_methods(["GET"])
@admin_groups_required('Security Admin')
def admin_roles_management(request):
    """Roles and permissions management page (uses Django Groups/Permissions).
    Visible to staff admins; role assignment to users will be superuser-gated in its endpoint.
    """
    groups = Group.objects.all().annotate(user_count=Count('user'))
    permissions = Permission.objects.select_related('content_type').order_by('content_type__app_label', 'codename')
    context = {
        'groups': groups,
        'permissions': permissions,
    }
    return render(request, 'admin/roles_management.html', context)
