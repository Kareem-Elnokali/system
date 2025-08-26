from urllib.parse import urlsplit, urlunsplit
from django.http import HttpResponseRedirect
from django.contrib import messages
class LocalhostRedirectMiddleware:
    """
    In development, WebAuthn over HTTP only works on the special origin 'http://localhost'.
    If the app is accessed via 127.0.0.1, redirect to the same URL on 'localhost'.
    """
    def __init__(self, get_response):
        self.get_response = get_response
    def __call__(self, request):
        host = request.get_host()
        path = request.path
        if host.startswith('127.0.0.1') and not path.startswith('/mfa/'):
            parts = urlsplit(request.build_absolute_uri())
            netloc = parts.netloc.replace('127.0.0.1', 'localhost')
            new_url = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
            return HttpResponseRedirect(new_url)
        return self.get_response(request)
class AnomalyDetectionMiddleware:
    """
    Detects session anomalies after authentication and surfaces a gentle banner via Django messages.
    Signals on:
      - Public IP change (compares first 2 octets as coarse geo proxy)
      - Device/User-Agent change
    Stores last-seen snapshot in session keys:
      _anomaly_ip, _anomaly_ip_prefix, _anomaly_ua
    """
    def __init__(self, get_response):
        self.get_response = get_response
    def __call__(self, request):
        response = self.get_response(request)
        try:
            self._process(request)
        except Exception:
            pass
        return response
    def _client_ip(self, request):
        xff = request.META.get('HTTP_X_FORWARDED_FOR')
        if xff:
            parts = [p.strip() for p in xff.split(',') if p.strip()]
            if parts:
                return parts[0]
        return request.META.get('REMOTE_ADDR') or ''
    def _ip_prefix(self, ip):
        if not ip:
            return ''
        if ':' in ip:
            hextets = ip.split(':')
            return ':'.join(hextets[:4])
        parts = ip.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[:2])
        return ip
    def _process(self, request):
        if not getattr(request, 'user', None) or not request.user.is_authenticated:
            return
        session = request.session
        ua = request.META.get('HTTP_USER_AGENT', '')[:256]
        ip = self._client_ip(request)
        ip_prefix = self._ip_prefix(ip)
        last_ip = session.get('_anomaly_ip')
        last_prefix = session.get('_anomaly_ip_prefix')
        last_ua = session.get('_anomaly_ua')
        anomalies = []
        if last_ip and ip and ip != last_ip:
            anomalies.append('network')
        if last_prefix and ip_prefix and ip_prefix != last_prefix:
            anomalies.append('location')
        if last_ua and ua and ua != last_ua:
            anomalies.append('device')
        session['_anomaly_ip'] = ip
        session['_anomaly_ip_prefix'] = ip_prefix
        session['_anomaly_ua'] = ua
        if anomalies:
            labels = {
                'network': 'network',
                'location': 'location',
                'device': 'device',
            }
            human = ', '.join(labels[a] for a in dict.fromkeys(anomalies))
            messages.warning(
                request,
                f"We noticed changes to your {human}. If this wasn't you, please secure your account."
            )
