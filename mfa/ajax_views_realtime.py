# Real-time AJAX endpoints for live monitoring
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from datetime import timedelta
from .decorators import admin_required
from .models import MFALog
from .security_models import (
    UserSession, SecurityIncident, UserBehavior, 
    ThreatIntelligence, APIUsage, SecurityNotification
)

@require_http_methods(["GET"])
@admin_required
def live_activity_feed(request):
    """Get live activity feed for real-time monitoring"""
    recent_activities = []
    
    # MFA events (last 10)
    recent_mfa_logs = MFALog.objects.select_related('user').order_by('-created_at')[:10]
    for log in recent_mfa_logs:
        # Normalize status based on event text
        ev = (log.event or '').lower()
        if 'success' in ev:
            status = 'success'
        elif 'fail' in ev or 'error' in ev:
            status = 'failure'
        else:
            status = 'warning'
        recent_activities.append({
            'type': 'mfa_event',
            'message': f"{log.user.username} - {log.event}",
            'timestamp': log.created_at.isoformat(),
            'status': status,
        })
    
    # Security incidents (last 10)
    recent_incidents = SecurityIncident.objects.select_related('user').order_by('-created_at')[:10]
    for incident in recent_incidents:
        # Map high severity to failure, others to warning for filter consistency
        status = 'failure' if getattr(incident, 'severity', '') == 'high' else 'warning'
        recent_activities.append({
            'type': 'security_incident',
            'message': f"Security Incident: {incident.incident_type} - {incident.user.username if incident.user else 'System'}",
            'timestamp': incident.created_at.isoformat(),
            'status': status,
        })
    
    # User behavior anomalies (last 5)
    recent_anomalies = UserBehavior.objects.filter(
        is_anomaly=True
    ).select_related('user').order_by('-timestamp')[:5]
    for anomaly in recent_anomalies:
        recent_activities.append({
            'type': 'anomaly',
            'message': f"Anomaly detected: {anomaly.user.username} - {anomaly.action}",
            'timestamp': anomaly.timestamp.isoformat(),
            'status': 'warning'
        })
    
    # Sort by timestamp
    recent_activities.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return JsonResponse({
        'success': True,
        'activities': recent_activities[:20]
    })

@require_http_methods(["GET"])
@admin_required
def live_system_stats(request):
    """Get live system statistics"""
    # Active sessions (last 30 minutes)
    active_sessions = UserSession.objects.filter(
        last_activity__gte=timezone.now() - timedelta(minutes=30)
    ).count()
    
    # Active threats (last 24 hours)
    active_threats = ThreatIntelligence.objects.filter(
        last_seen__gte=timezone.now() - timedelta(hours=24)
    ).count()
    
    # Recent anomalies (last hour)
    recent_anomalies = UserBehavior.objects.filter(
        is_anomaly=True,
        timestamp__gte=timezone.now() - timedelta(hours=1)
    ).count()
    
    # API health (last hour)
    api_calls_total = APIUsage.objects.filter(
        timestamp__gte=timezone.now() - timedelta(hours=1)
    ).count()
    api_calls_success = APIUsage.objects.filter(
        timestamp__gte=timezone.now() - timedelta(hours=1),
        status_code__lt=400
    ).count()
    api_health = (api_calls_success / api_calls_total * 100) if api_calls_total > 0 else 100
    
    # Unread notifications
    unread_notifications = SecurityNotification.objects.filter(is_read=False).count()
    
    return JsonResponse({
        'success': True,
        'stats': {
            'active_sessions': active_sessions,
            'active_threats': active_threats,
            'recent_anomalies': recent_anomalies,
            'api_health': round(api_health, 1),
            'unread_notifications': unread_notifications,
            'timestamp': timezone.now().isoformat()
        }
    })

@require_http_methods(["GET"])
@admin_required
def live_session_data(request):
    """Get live session data for charts"""
    # Sessions by hour (last 24 hours)
    session_data = []
    for i in range(24):
        hour_start = timezone.now() - timedelta(hours=i+1)
        hour_end = timezone.now() - timedelta(hours=i)
        count = UserSession.objects.filter(
            created_at__gte=hour_start,
            created_at__lt=hour_end
        ).count()
        session_data.append({
            'hour': hour_start.strftime('%H:00'),
            'count': count
        })
    
    session_data.reverse()
    
    return JsonResponse({
        'success': True,
        'session_data': session_data
    })

@require_http_methods(["GET"])
@admin_required
def live_threat_data(request):
    """Get live threat data for charts"""
    # Threats by type
    threat_types = ThreatIntelligence.objects.filter(
        last_seen__gte=timezone.now() - timedelta(days=7)
    ).values('threat_type').distinct()
    
    threat_data = []
    for threat_type in threat_types:
        count = ThreatIntelligence.objects.filter(
            threat_type=threat_type['threat_type'],
            last_seen__gte=timezone.now() - timedelta(days=7)
        ).count()
        threat_data.append({
            'type': threat_type['threat_type'],
            'count': count
        })
    
    return JsonResponse({
        'success': True,
        'threat_data': threat_data
    })
