from __future__ import annotations
from django.contrib.admin.views.decorators import staff_member_required
from django.db.models import Count
from django.http import JsonResponse, HttpRequest
from django.utils import timezone
from datetime import timedelta
import re
from django.contrib.auth import get_user_model

from .models import MFALog, MFADevice
from .security_models import SecurityIncident, ComplianceReport
from .views_advanced import calculate_user_risk_score


UA_MOBILE_RE = re.compile(r"iphone|android.+mobile|windows phone|ipod", re.I)
UA_TABLET_RE = re.compile(r"ipad|android(?!.*mobile)|tablet", re.I)


def _bucket_user_agent(ua: str | None) -> str:
    if not ua:
        return "Unknown"
    ua_l = ua.lower()
    if UA_TABLET_RE.search(ua_l):
        return "Tablet"
    if UA_MOBILE_RE.search(ua_l):
        return "Mobile"
    if "windows" in ua_l or "mac os" in ua_l or "linux" in ua_l or "x11" in ua_l:
        return "Desktop"
    return "Unknown"


@staff_member_required
def api_device_types(request: HttpRequest) -> JsonResponse:
    qs = MFALog.objects.values_list("user_agent", flat=True)[:5000]
    counts = {"Desktop": 0, "Mobile": 0, "Tablet": 0, "Unknown": 0}
    for ua in qs:
        counts[_bucket_user_agent(ua)] += 1
    labels = list(counts.keys())
    data = [counts[k] for k in labels]
    return JsonResponse({"labels": labels, "counts": data})


@staff_member_required
def api_risk_distribution(request: HttpRequest) -> JsonResponse:
    # Simple distribution by success/failure classes from MFALog
    buckets = {
        "Success": MFALog.objects.filter(event__endswith="success").count(),
        "Failure": MFALog.objects.filter(event__endswith="failure").count(),
        "Other": MFALog.objects.exclude(event__endswith="success").exclude(event__endswith="failure").count(),
    }
    labels = list(buckets.keys())
    counts = [buckets[k] for k in labels]
    return JsonResponse({"labels": labels, "counts": counts})


@staff_member_required
def api_logs_summary(request: HttpRequest) -> JsonResponse:
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    total_logs = MFALog.objects.count()
    logs_24h = MFALog.objects.filter(created_at__gte=last_24h).count()
    unique_users = MFALog.objects.exclude(user=None).values("user").distinct().count()
    devices = MFADevice.objects.count()
    return JsonResponse({
        "total_logs": total_logs,
        "logs_24h": logs_24h,
        "unique_users": unique_users,
        "devices": devices,
    })


# Incident Response APIs

@staff_member_required
def api_incidents_summary(request: HttpRequest) -> JsonResponse:
    open_cnt = SecurityIncident.objects.filter(status='open').count()
    resolved_cnt = SecurityIncident.objects.filter(status='resolved').count()
    in_prog_cnt = SecurityIncident.objects.filter(status='investigating').count()
    critical_cnt = SecurityIncident.objects.filter(severity='critical').count()
    return JsonResponse({
        "open": open_cnt,
        "resolved": resolved_cnt,
        "in_progress": in_prog_cnt,
        "critical": critical_cnt,
    })


@staff_member_required
def api_incidents_active(request: HttpRequest) -> JsonResponse:
    items = list(
        SecurityIncident.objects.exclude(status='resolved')
        .order_by('-created_at')
        .values('incident_id', 'incident_type', 'severity', 'status', 'assigned_to_id', 'created_at')[:50]
    )
    # Basic label mapping
    for it in items:
        it['assigned_to'] = str(it.pop('assigned_to_id')) if it.get('assigned_to_id') else None
        it['created_ago'] = timezone.now() - it['created_at']
        it['created_ago_seconds'] = int(it['created_ago'].total_seconds())
        it['created_at'] = it['created_at'].isoformat()
    return JsonResponse({"items": items})


@staff_member_required
def api_incident_categories(request: HttpRequest) -> JsonResponse:
    qs = SecurityIncident.objects.values('incident_type').annotate(c=Count('id')).order_by('-c')
    labels = [row['incident_type'] for row in qs]
    counts = [row['c'] for row in qs]
    return JsonResponse({"labels": labels, "counts": counts})


@staff_member_required
def api_incident_timeline(request: HttpRequest) -> JsonResponse:
    # Simple timeline from incident create/resolve events
    items = list(SecurityIncident.objects.order_by('-created_at').values('incident_id', 'severity', 'status', 'created_at')[:20])
    timeline = [
        {
            "title": "Incident Created",
            "incident_id": it['incident_id'],
            "severity": it['severity'],
            "status": it['status'],
            "ts": it['created_at'].isoformat(),
        }
        for it in items
    ]
    return JsonResponse({"events": timeline})


@staff_member_required
def api_incident_update(request: HttpRequest) -> JsonResponse:
    """Update an incident's status/assignee and optionally append a note.
    Accepts POST JSON or form data with keys:
      - incident_id (required)
      - status (optional; one of SecurityIncident.STATUS_CHOICES)
      - assignee_user_id (optional; int)
      - note (optional; string)
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    incident_id = request.POST.get('incident_id') or None
    if not incident_id:
        # try JSON body
        try:
            import json as _json
            payload = _json.loads(request.body.decode('utf-8')) if request.body else {}
        except Exception:
            payload = {}
        incident_id = payload.get('incident_id')
        status_new = payload.get('status')
        assignee_user_id = payload.get('assignee_user_id')
        note = payload.get('note')
    else:
        status_new = request.POST.get('status')
        assignee_user_id = request.POST.get('assignee_user_id')
        note = request.POST.get('note')

    if not incident_id:
        return JsonResponse({'error': 'incident_id required'}, status=400)

    inc = SecurityIncident.objects.filter(incident_id=incident_id).first()
    if not inc:
        return JsonResponse({'error': 'Incident not found'}, status=404)

    # Update fields
    changed = False
    if status_new:
        valid_status = {k for k, _ in SecurityIncident.STATUS_CHOICES}
        if status_new not in valid_status:
            return JsonResponse({'error': 'Invalid status'}, status=400)
        inc.status = status_new
        # set resolved_at when transitioning to resolved
        from django.utils import timezone as _tz
        inc.resolved_at = _tz.now() if status_new == 'resolved' else inc.resolved_at
        changed = True

    if assignee_user_id:
        try:
            assignee_user_id = int(assignee_user_id)
        except Exception:
            return JsonResponse({'error': 'assignee_user_id must be int'}, status=400)
        from django.contrib.auth import get_user_model
        User = get_user_model()
        assignee = User.objects.filter(id=assignee_user_id).first()
        if not assignee:
            return JsonResponse({'error': 'Assignee not found'}, status=404)
        inc.assigned_to = assignee
        changed = True

    if note:
        # append note into details.notes list
        from django.utils import timezone as _tz
        details = (inc.details or {}).copy()
        notes = details.get('notes') or []
        notes.append({
            'ts': _tz.now().isoformat(),
            'by': getattr(request.user, 'username', 'system'),
            'note': str(note)[:2000],
        })
        details['notes'] = notes
        inc.details = details
        changed = True

    if changed:
        inc.save()

    data = {
        'incident_id': inc.incident_id,
        'incident_type': inc.incident_type,
        'severity': inc.severity,
        'status': inc.status,
        'assigned_to': inc.assigned_to_id,
        'created_at': inc.created_at.isoformat() if inc.created_at else None,
        'updated_at': inc.updated_at.isoformat() if inc.updated_at else None,
        'resolved_at': inc.resolved_at.isoformat() if inc.resolved_at else None,
    }
    return JsonResponse({'ok': True, 'incident': data})


# Forensics & Compliance APIs

@staff_member_required
def api_forensics_summary(request: HttpRequest) -> JsonResponse:
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    total_logs = MFALog.objects.count()
    logs_24h = MFALog.objects.filter(created_at__gte=last_24h).count()
    active_investigations = SecurityIncident.objects.filter(status='investigating').count()
    return JsonResponse({
        "total_logs": total_logs,
        "logs_24h": logs_24h,
        "active_investigations": active_investigations,
    })


@staff_member_required
def api_compliance_status(request: HttpRequest) -> JsonResponse:
    # Latest score per report_type
    latest_scores = {}
    types = [t for t, _ in ComplianceReport.REPORT_TYPES]
    for t in types:
        row = ComplianceReport.objects.filter(report_type=t).order_by('-generated_at').values('compliance_score').first()
        latest_scores[t] = row['compliance_score'] if row else None
    return JsonResponse({"scores": latest_scores})


# ML Risk (derived from logs as a proxy)

@staff_member_required
def api_ml_summary(request: HttpRequest) -> JsonResponse:
    failures = MFALog.objects.filter(event__endswith='failure').count()
    successes = MFALog.objects.filter(event__endswith='success').count()
    total = failures + successes or 1
    risk_score = round(100.0 * failures / total, 2)
    return JsonResponse({
        "risk_score": risk_score,
        "successes": successes,
        "failures": failures,
    })


# Account Security Score APIs

def _risk_level_and_color(score: int) -> tuple[str, str]:
    level = 'Critical' if score >= 80 else 'High' if score >= 60 else 'Medium' if score >= 30 else 'Low'
    color = 'danger' if score >= 80 else 'warning' if score >= 60 else 'info' if score >= 30 else 'success'
    return level, color


@staff_member_required
def api_user_security_score(request: HttpRequest, user_id: int) -> JsonResponse:
    """Return risk/security score and details for a single user.
    Payload: { id, risk_score, risk_level, risk_color, recent_failures, has_mfa }
    """
    User = get_user_model()
    u = User.objects.filter(id=user_id).first()
    if not u:
        return JsonResponse({"error": "User not found"}, status=404)
    score = int(calculate_user_risk_score(u))
    # recent failures last 7 days
    last_7d = timezone.now() - timedelta(days=7)
    failures = MFALog.objects.filter(user_id=u.id, event__contains='failure', created_at__gte=last_7d).count()
    has_mfa = MFADevice.objects.filter(user_id=u.id, confirmed=True).exists()
    level, color = _risk_level_and_color(score)
    return JsonResponse({
        "id": u.id,
        "risk_score": score,
        "risk_level": level,
        "risk_color": color,
        "recent_failures": failures,
        "has_mfa": bool(has_mfa),
    })


@staff_member_required
def api_users_security_scores(request: HttpRequest) -> JsonResponse:
    """Return risk/security scores for a set of users.
    Accepts JSON body: { "ids": [int, ...] }
    Returns: { "results": { "<id>": {risk_score, risk_level, risk_color, recent_failures, has_mfa} } }
    """
    try:
        data = request.body.decode('utf-8') if request.body else ''
    except Exception:
        data = ''
    import json as _json
    try:
        payload = _json.loads(data) if data else {}
    except Exception:
        payload = {}
    ids = payload.get('ids') or []
    if not isinstance(ids, list) or not ids:
        return JsonResponse({"error": "Provide ids list"}, status=400)
    try:
        ids = [int(x) for x in ids]
    except Exception:
        return JsonResponse({"error": "Invalid ids"}, status=400)
    User = get_user_model()
    users = list(User.objects.filter(id__in=ids))
    if not users:
        return JsonResponse({"results": {}})
    # Precompute
    last_7d = timezone.now() - timedelta(days=7)
    failures_map = {
        row['user_id']: row['c']
        for row in MFALog.objects.filter(
            user_id__in=ids, event__contains='failure', created_at__gte=last_7d
        ).values('user_id').annotate(c=Count('id'))
    }
    has_mfa_ids = set(MFADevice.objects.filter(user_id__in=ids, confirmed=True).values_list('user_id', flat=True))
    results = {}
    for u in users:
        score = int(calculate_user_risk_score(u))
        level, color = _risk_level_and_color(score)
        results[str(u.id)] = {
            "risk_score": score,
            "risk_level": level,
            "risk_color": color,
            "recent_failures": int(failures_map.get(u.id, 0)),
            "has_mfa": bool(u.id in has_mfa_ids),
        }
    return JsonResponse({"results": results})


@staff_member_required
def api_audit_event_detail(request: HttpRequest) -> JsonResponse:
    """
    Fetch details for an audit item used by the Forensics & Audit modal.
    Accepts either:
      - incident_id (SecurityIncident.incident_id)
      - log_id (MFALog.id)
    Returns a normalized JSON payload for the UI.
    """
    incident_id = request.GET.get('incident_id')
    log_id = request.GET.get('log_id')

    if incident_id:
        inc = SecurityIncident.objects.filter(incident_id=incident_id).values(
            'incident_id', 'incident_type', 'severity', 'status', 'created_at',
            'user_id', 'ip_address', 'user_agent'
        ).first()
        if not inc:
            return JsonResponse({'error': 'Incident not found'}, status=404)
        data = {
            'type': 'incident',
            'id': inc['incident_id'],
            'timestamp': inc['created_at'].isoformat() if inc.get('created_at') else None,
            'event_type': inc.get('incident_type'),
            'user': str(inc.get('user_id') or ''),
            'ip_address': inc.get('ip_address'),
            'user_agent': inc.get('user_agent'),
            'severity': inc.get('severity'),
            'status': inc.get('status'),
            'raw': inc,
        }
        return JsonResponse(data)

    if log_id:
        log = MFALog.objects.filter(id=log_id).values(
            'id', 'event', 'user_id', 'ip_address', 'user_agent', 'created_at', 'metadata'
        ).first()
        if not log:
            return JsonResponse({'error': 'Log not found'}, status=404)
        data = {
            'type': 'log',
            'id': log['id'],
            'timestamp': log['created_at'].isoformat() if log.get('created_at') else None,
            'event_type': log.get('event'),
            'user': str(log.get('user_id') or ''),
            'ip_address': log.get('ip_address'),
            'user_agent': log.get('user_agent'),
            'severity': None,
            'status': None,
            'raw': log.get('metadata'),
        }
        return JsonResponse(data)

    return JsonResponse({'error': 'Provide incident_id or log_id'}, status=400)
