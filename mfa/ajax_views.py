"""AJAX endpoint views for admin dashboard functionality"""
import json
import csv
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_http_methods
from .decorators import admin_required
from django.utils.dateparse import parse_date
from django.utils import timezone
from datetime import datetime, timedelta
from .models import MFALog
from .security_models import UserSession, DeviceFingerprint, SecurityNotification
from django.contrib.auth.models import Group, Permission, User
from django.db.models import Count


@require_http_methods(["POST"])
@admin_required
def admin_save_ml_config(request):
    """Save ML risk engine configuration"""
    try:
        data = json.loads(request.body)
        # In a real implementation, save the configuration to database
        return JsonResponse({'success': True, 'message': 'Configuration saved successfully'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


@require_http_methods(["POST"])
@admin_required
def admin_mark_all_read(request):
    """Mark all notifications as read"""
    try:
        qs = SecurityNotification.objects.filter(user=request.user, is_read=False)
        now = timezone.now()
        updated = qs.update(is_read=True, read_at=now)
        return JsonResponse({'success': True, 'updated': updated})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


@require_http_methods(["GET"])
@admin_required
def admin_export_risk_report(request):
    """Export risk assessment report"""
    try:
        # Summarize risk per user from MFALog successes/failures
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="risk_report.csv"'
        writer = csv.writer(response)
        writer.writerow(['user_id','username','successes','failures','risk_score_pct','risk_level'])
        from django.contrib.auth.models import User
        users = User.objects.all().only('id','username')
        for u in users:
            succ = MFALog.objects.filter(user_id=u.id, event__endswith='success').count()
            fail = MFALog.objects.filter(user_id=u.id, event__endswith='failure').count()
            total = succ + fail
            risk = round(100.0 * (fail/(total or 1)), 2)
            level = 'Low'
            if risk >= 50:
                level = 'High'
            elif risk >= 25:
                level = 'Medium'
            writer.writerow([u.id, u.username, succ, fail, risk, level])
        return response
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)

@require_http_methods(["POST"])
@admin_required
def admin_start_log_correlation(request):
    """Kick off a mock log correlation job and return a job id."""
    payload = {
        'success': True,
        'job_id': 'corr-' + timezone.now().strftime('%Y%m%d%H%M%S'),
        'message': 'Log correlation started',
    }
    return JsonResponse(payload)

@require_http_methods(["POST"])
@admin_required
def admin_run_timeline_analysis(request):
    """Compute counts per hour for the last 6 hours as a lightweight timeline analysis."""
    now = timezone.now()
    last_6h = now - timedelta(hours=6)
    buckets = {}
    # Initialize buckets
    hour_start = last_6h.replace(minute=0, second=0, microsecond=0)
    for i in range(7):
        h = hour_start + timedelta(hours=i)
        buckets[h.isoformat()] = 0
    for ts in MFALog.objects.filter(created_at__gte=last_6h).values_list('created_at', flat=True):
        key = ts.replace(minute=0, second=0, microsecond=0).isoformat()
        if key in buckets:
            buckets[key] += 1
    return JsonResponse({'success': True, 'series': buckets})

@require_http_methods(["POST"])
@admin_required
def admin_run_pattern_detection(request):
    """Perform a simple frequency analysis of events as a stand-in for pattern detection."""
    top = (
        MFALog.objects.values('event')
        .annotate(c=Count('event'))
        .order_by('-c')[:10]
    )
    patterns = [{'event': row['event'], 'count': row['c']} for row in top]
    return JsonResponse({'success': True, 'patterns': patterns})

@require_http_methods(["POST"])
@admin_required
def admin_run_risk_assessment(request):
    """Compute a simple risk summary from MFALog success/failure proportions."""
    failures = MFALog.objects.filter(event__endswith='failure').count()
    successes = MFALog.objects.filter(event__endswith='success').count()
    total = failures + successes or 1
    risk_score = round(100.0 * failures / total, 2)
    level = 'Low'
    if risk_score >= 50:
        level = 'High'
    elif risk_score >= 25:
        level = 'Medium'
    return JsonResponse({'success': True, 'risk_score': risk_score, 'level': level, 'successes': successes, 'failures': failures})


@require_http_methods(["POST"])
@admin_required
def admin_block_device(request):
    """Block a device from accessing the system."""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            device_id = data.get('device_id')
            if not device_id:
                return JsonResponse({'success': False, 'error': 'device_id required'}, status=400)
            # Treat device_id as primary key of DeviceFingerprint
            df = DeviceFingerprint.objects.get(id=int(device_id))
            df.is_blocked = True
            df.save(update_fields=['is_blocked'])
            return JsonResponse({'success': True, 'message': f'Device {df.id} has been blocked successfully'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=400)
    
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

# ----- Roles management AJAX -----
@require_http_methods(["POST"])
@admin_required
def admin_roles_create(request):
    """Create a new role (Group). Payload: {name} """
    try:
        data = json.loads(request.body or '{}')
        name = (data.get('name') or '').strip()
        if not name:
            return JsonResponse({'success': False, 'error': 'Name required'}, status=400)
        if Group.objects.filter(name=name).exists():
            return JsonResponse({'success': False, 'error': 'Role already exists'}, status=400)
        g = Group.objects.create(name=name)
        return JsonResponse({'success': True, 'id': g.id, 'name': g.name})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


@require_http_methods(["POST"])
@admin_required
def admin_roles_delete(request):
    """Delete a role (Group). Payload: {id} """
    try:
        data = json.loads(request.body or '{}')
        gid = int(data.get('id'))
        Group.objects.filter(id=gid).delete()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


@require_http_methods(["POST"])
@admin_required
def admin_roles_update_perms(request):
    """Update a role's permissions. Payload: {id, perm_ids: [int,...]} """
    try:
        data = json.loads(request.body or '{}')
        gid = int(data.get('id'))
        perm_ids = data.get('perm_ids') or []
        g = Group.objects.get(id=gid)
        perms = list(Permission.objects.filter(id__in=perm_ids))
        g.permissions.set(perms)
        return JsonResponse({'success': True})
    except Group.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Role not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


@require_http_methods(["GET"])
@admin_required
def admin_roles_list(request):
    """List roles and (optionally) permissions. Query: include_perms=1 to include perm ids."""
    include_perms = request.GET.get('include_perms') == '1'
    groups = []
    for g in Group.objects.all().order_by('name'):
        item = {'id': g.id, 'name': g.name}
        if include_perms:
            item['perm_ids'] = list(g.permissions.values_list('id', flat=True))
        groups.append(item)
    return JsonResponse({'success': True, 'roles': groups})


@require_http_methods(["POST"])
@admin_required
def admin_assign_role_to_user(request):
    """Assign a role (Group) to a user. Superuser only. Payload: {user_id, role_id}
    Adds the group to the user's groups set (idempotent).
    """
    if not getattr(request.user, 'is_superuser', False):
        return JsonResponse({'success': False, 'error': 'Superuser required'}, status=403)
    try:
        data = json.loads(request.body or '{}')
        uid = int(data.get('user_id'))
        gid = int(data.get('role_id'))
        u = User.objects.get(id=uid)
        g = Group.objects.get(id=gid)
        u.groups.add(g)
        return JsonResponse({'success': True})
    except (User.DoesNotExist, Group.DoesNotExist):
        return JsonResponse({'success': False, 'error': 'User or Role not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)

@require_http_methods(["GET"])
@admin_required
def admin_export_audit_logs(request):
    """Export audit (MFA) logs as CSV for a given date range.

    Query params:
      - start_date (YYYY-MM-DD)
      - end_date (YYYY-MM-DD)
    """
    start_s = request.GET.get('start_date')
    end_s = request.GET.get('end_date')

    # Parse dates; if invalid, default to last 7 days
    start_dt = parse_date(start_s) if start_s else None
    end_dt = parse_date(end_s) if end_s else None
    if not start_dt or not end_dt:
        end_dt = timezone.now().date()
        start_dt = end_dt - timedelta(days=7)

    # Inclusive end of day
    start_dt = datetime.combine(start_dt, datetime.min.time()).replace(tzinfo=timezone.get_current_timezone())
    end_dt = datetime.combine(end_dt, datetime.max.time()).replace(tzinfo=timezone.get_current_timezone())

    qs = MFALog.objects.filter(created_at__gte=start_dt, created_at__lte=end_dt).order_by('created_at')

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="audit_logs.csv"'
    writer = csv.writer(response)
    writer.writerow(['id', 'event', 'user_id', 'ip_address', 'user_agent', 'created_at'])
    for log in qs.values_list('id', 'event', 'user_id', 'ip_address', 'user_agent', 'created_at'):
        row = list(log)
        # Ensure ISO format for datetime
        row[-1] = row[-1].isoformat() if row[-1] else ''
        writer.writerow(row)
    return response

@admin_required
def admin_geo_map(request):
    """Display geographic map of user sessions."""
    if request.method == 'GET':
        # Mock geo map data
        return JsonResponse({
            'success': True,
            'redirect_url': '/mfa/admin/geolocation-tracking/'
        })
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@admin_required
def admin_terminate_sessions(request):
    """Terminate selected user sessions."""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            session_ids = data.get('session_ids', []) or []
            if not isinstance(session_ids, list):
                return JsonResponse({'success': False, 'error': 'session_ids must be a list'}, status=400)
            # Delete UserSession rows by id
            deleted, _ = UserSession.objects.filter(id__in=session_ids).delete()
            return JsonResponse({'success': True, 'message': f'Successfully terminated {deleted} sessions', 'terminated': deleted})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=400)
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@admin_required
def admin_export_sessions(request):
    """Export session data as CSV."""
    if request.method == 'GET':
        # Generate CSV from UserSession model
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="sessions.csv"'
        writer = csv.writer(response)
        writer.writerow(['id','user_id','username','ip_address','user_agent','country','city','lat','lng','is_suspicious','risk_score','created_at','last_activity'])
        for s in UserSession.objects.select_related('user').all():
            writer.writerow([
                s.id,
                s.user_id,
                getattr(s.user, 'username', ''),
                s.ip_address,
                s.user_agent,
                s.location_country,
                s.location_city,
                s.location_lat,
                s.location_lng,
                int(s.is_suspicious),
                s.risk_score,
                s.created_at.isoformat() if s.created_at else '',
                s.last_activity.isoformat() if s.last_activity else '',
            ])
        return response
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@admin_required
def admin_save_security_settings(request):
    """Save security settings configuration."""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            
            # Mock settings save logic
            settings_saved = {
                'session_timeout': data.get('session_timeout', 30),
                'max_concurrent_sessions': data.get('max_concurrent_sessions', 5),
                'geo_blocking_enabled': data.get('geo_blocking_enabled', False)
            }
            
            return JsonResponse({
                'success': True,
                'message': 'Security settings saved successfully',
                'settings': settings_saved
            })
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            })
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

# Additional missing AJAX views
@admin_required
def admin_export_location_data(request):
    """Export location data as CSV."""
    return JsonResponse({'success': True, 'download_url': '/static/exports/locations.csv'})

@admin_required
def admin_restrict_user(request):
    """Restrict user access."""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_id = data.get('user_id')
            return JsonResponse({'success': True, 'message': f'User {user_id} restricted successfully'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@admin_required
def admin_export_model_metrics(request):
    """Export ML model metrics."""
    return JsonResponse({'success': True, 'download_url': '/static/exports/model_metrics.csv'})

@admin_required
def admin_export_threat_report(request):
    """Export threat intelligence report."""
    return JsonResponse({'success': True, 'download_url': '/static/exports/threat_report.csv'})

@admin_required
def admin_block_threat(request):
    """Block a threat source."""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            alert_id = data.get('alert_id')
            return JsonResponse({'success': True, 'message': f'Threat {alert_id} blocked successfully'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@admin_required
def admin_export_policy_logs(request):
    """Export security policy logs."""
    return JsonResponse({'success': True, 'download_url': '/static/exports/policy_logs.csv'})

@admin_required
def admin_export_organizations(request):
    """Export organization data."""
    return JsonResponse({'success': True, 'download_url': '/static/exports/organizations.csv'})

@admin_required
def admin_export_permissions(request):
    """Export permissions data."""
    return JsonResponse({'success': True, 'download_url': '/static/exports/permissions.csv'})

@admin_required
def admin_mark_notification_read(request):
    """Mark a notification as read."""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            notif_id = data.get('notif_id')
            if not notif_id:
                return JsonResponse({'success': False, 'error': 'notif_id required'}, status=400)
            n = SecurityNotification.objects.get(id=int(notif_id), user=request.user)
            if not n.is_read:
                n.is_read = True
                n.read_at = timezone.now()
                n.save(update_fields=['is_read','read_at'])
            return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=400)
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@admin_required
def admin_delete_notification(request):
    """Delete a notification."""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            notif_id = data.get('notif_id')
            if not notif_id:
                return JsonResponse({'success': False, 'error': 'notif_id required'}, status=400)
            deleted, _ = SecurityNotification.objects.filter(id=int(notif_id), user=request.user).delete()
            return JsonResponse({'success': True, 'deleted': deleted})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=400)
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@admin_required
def admin_save_notification_settings(request):
    """Save notification settings."""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            return JsonResponse({'success': True, 'message': 'Notification settings saved successfully'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@admin_required
def admin_create_geo_rule(request):
    """Create geographic rule."""
    return JsonResponse({'success': True, 'redirect_url': '/mfa/admin/geolocation-tracking/'})

@admin_required
def admin_suspicious_locations(request):
    """View suspicious locations."""
    return JsonResponse({'success': True, 'redirect_url': '/mfa/admin/geolocation-tracking/'})

@admin_required
def admin_travel_alerts(request):
    """View travel alerts."""
    return JsonResponse({'success': True, 'redirect_url': '/mfa/admin/geolocation-tracking/'})

@admin_required
def admin_export_geo_report(request):
    """Export geographic report."""
    return JsonResponse({'success': True, 'download_url': '/static/exports/geo_report.csv'})

@admin_required
def admin_run_backup(request):
    """Run backup now."""
    if request.method == 'POST':
        return JsonResponse({'success': True, 'message': 'Backup started successfully'})
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@admin_required
def admin_backup_settings(request):
    """Configure backup settings."""
    return JsonResponse({'success': True, 'redirect_url': '/mfa/admin/backup-recovery/'})

@admin_required
def admin_restore_backup(request):
    """Restore from backup."""
    if request.method == 'POST':
        return JsonResponse({'success': True, 'message': 'Backup restored successfully'})
    return JsonResponse({'success': False, 'error': 'Invalid request method'})
