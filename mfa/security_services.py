"""Security services for real implementation of advanced features"""
import requests
import hashlib
import json
from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings
from django.contrib.auth.models import User
from django.db.models import Count, Q, Avg
from .security_models import (
    UserSession, ThreatIntelligence, UserBehavior, DeviceFingerprint,
    SecurityIncident, SecurityNotification, APIUsage, ComplianceReport
)
from .models import MFALog
import logging

logger = logging.getLogger(__name__)


class SessionTrackingService:
    """Real session management and tracking"""
    
    @staticmethod
    def create_session(user, request):
        """Create or update user session with geolocation"""
        ip_address = SessionTrackingService.get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        device_fingerprint = SessionTrackingService.generate_device_fingerprint(request)
        
        # Get geolocation
        location_data = GeolocationService.get_location(ip_address)
        
        session, created = UserSession.objects.update_or_create(
            user=user,
            session_key=request.session.session_key,
            defaults={
                'ip_address': ip_address,
                'user_agent': user_agent,
                'device_fingerprint': device_fingerprint,
                'location_country': location_data.get('country', ''),
                'location_city': location_data.get('city', ''),
                'location_lat': location_data.get('lat'),
                'location_lng': location_data.get('lng'),
                'last_activity': timezone.now(),
                'risk_score': RiskAssessmentService.calculate_session_risk(user, ip_address, location_data)
            }
        )
        
        # Check for suspicious activity
        if SessionTrackingService.is_suspicious_session(user, session):
            session.is_suspicious = True
            session.save()
            SecurityIncidentService.create_incident(
                'suspicious_login', 'medium', user, ip_address,
                f"Suspicious login detected for user {user.username}"
            )
        
        return session
    
    @staticmethod
    def get_client_ip(request):
        """Get real client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    @staticmethod
    def generate_device_fingerprint(request):
        """Generate device fingerprint from request headers"""
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        accept_language = request.META.get('HTTP_ACCEPT_LANGUAGE', '')
        accept_encoding = request.META.get('HTTP_ACCEPT_ENCODING', '')
        
        fingerprint_data = f"{user_agent}|{accept_language}|{accept_encoding}"
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()
    
    @staticmethod
    def is_suspicious_session(user, session):
        """Check if session is suspicious based on patterns"""
        # Check for new location
        recent_sessions = UserSession.objects.filter(
            user=user,
            created_at__gte=timezone.now() - timedelta(days=30)
        ).exclude(id=session.id)
        
        if recent_sessions.exists():
            # Check if location is new
            known_countries = set(recent_sessions.values_list('location_country', flat=True))
            if session.location_country and session.location_country not in known_countries:
                return True
        
        # Check threat intelligence
        if ThreatIntelligenceService.is_threat_ip(session.ip_address):
            return True
        
        return False
    
    @staticmethod
    def get_active_sessions(user=None):
        """Get active sessions with real data"""
        query = UserSession.objects.filter(
            last_activity__gte=timezone.now() - timedelta(hours=24)
        )
        if user:
            query = query.filter(user=user)
        
        return query.select_related('user').order_by('-last_activity')


class GeolocationService:
    """IP geolocation service"""
    
    @staticmethod
    def get_location(ip_address):
        """Get location data for IP address"""
        try:
            # Using ipapi.co (free tier available)
            response = requests.get(f'https://ipapi.co/{ip_address}/json/', timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country_code', ''),
                    'city': data.get('city', ''),
                    'lat': data.get('latitude'),
                    'lng': data.get('longitude'),
                    'region': data.get('region', ''),
                    'timezone': data.get('timezone', '')
                }
        except Exception as e:
            logger.error(f"Geolocation lookup failed for {ip_address}: {e}")
        
        return {}


class ThreatIntelligenceService:
    """Threat intelligence and IP reputation checking"""
    
    @staticmethod
    def check_ip_reputation(ip_address):
        """Check IP reputation using multiple sources"""
        threat_data = ThreatIntelligence.objects.filter(ip_address=ip_address).first()
        
        if not threat_data or threat_data.updated_at < timezone.now() - timedelta(hours=24):
            # Update threat intelligence
            threat_data = ThreatIntelligenceService.fetch_threat_data(ip_address)
        
        return threat_data
    
    @staticmethod
    def fetch_threat_data(ip_address):
        """Fetch threat data from external APIs"""
        try:
            # Using AbuseIPDB API (requires API key)
            if hasattr(settings, 'ABUSEIPDB_API_KEY'):
                headers = {
                    'Key': settings.ABUSEIPDB_API_KEY,
                    'Accept': 'application/json'
                }
                params = {
                    'ipAddress': ip_address,
                    'maxAgeInDays': 90,
                    'verbose': ''
                }
                
                response = requests.get(
                    'https://api.abuseipdb.com/api/v2/check',
                    headers=headers,
                    params=params,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json().get('data', {})
                    threat_score = data.get('abuseConfidencePercentage', 0)
                    
                    threat_data, created = ThreatIntelligence.objects.update_or_create(
                        ip_address=ip_address,
                        defaults={
                            'threat_score': threat_score,
                            'source': 'AbuseIPDB',
                            'last_seen': timezone.now(),
                            'is_blocked': threat_score > 75,
                            'threat_type': 'scanner' if threat_score > 50 else 'unknown'
                        }
                    )
                    return threat_data
        except Exception as e:
            logger.error(f"Threat intelligence lookup failed for {ip_address}: {e}")
        
        return None
    
    @staticmethod
    def is_threat_ip(ip_address):
        """Check if IP is a known threat"""
        threat = ThreatIntelligence.objects.filter(
            ip_address=ip_address,
            threat_score__gte=50
        ).first()
        return threat is not None


class UserBehaviorService:
    """User behavior analysis and anomaly detection"""
    
    @staticmethod
    def log_behavior(user, action, request):
        """Log user behavior for analysis"""
        ip_address = SessionTrackingService.get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        device_fingerprint = SessionTrackingService.generate_device_fingerprint(request)
        location_data = GeolocationService.get_location(ip_address)
        
        behavior = UserBehavior.objects.create(
            user=user,
            action=action,
            ip_address=ip_address,
            user_agent=user_agent,
            device_fingerprint=device_fingerprint,
            location_country=location_data.get('country', ''),
            location_city=location_data.get('city', ''),
            timestamp=timezone.now()
        )
        
        # Analyze for anomalies
        UserBehaviorService.analyze_anomalies(behavior)
        return behavior
    
    @staticmethod
    def analyze_anomalies(behavior):
        """Analyze behavior for anomalies"""
        anomaly_reasons = []
        anomaly_score = 0.0
        
        # Check for unusual location
        recent_behaviors = UserBehavior.objects.filter(
            user=behavior.user,
            timestamp__gte=timezone.now() - timedelta(days=30)
        ).exclude(id=behavior.id)
        
        if recent_behaviors.exists():
            known_countries = set(recent_behaviors.values_list('location_country', flat=True))
            if behavior.location_country and behavior.location_country not in known_countries:
                anomaly_reasons.append('New location detected')
                anomaly_score += 0.3
        
        # Check for unusual time
        user_login_hours = recent_behaviors.filter(action='login').values_list('timestamp__hour', flat=True)
        if user_login_hours and behavior.action == 'login':
            avg_hour = sum(user_login_hours) / len(user_login_hours)
            current_hour = behavior.timestamp.hour
            if abs(current_hour - avg_hour) > 6:
                anomaly_reasons.append('Unusual login time')
                anomaly_score += 0.2
        
        # Check for rapid successive actions
        recent_actions = UserBehavior.objects.filter(
            user=behavior.user,
            timestamp__gte=timezone.now() - timedelta(minutes=5)
        ).count()
        
        if recent_actions > 10:
            anomaly_reasons.append('Rapid successive actions')
            anomaly_score += 0.4
        
        # Update behavior record
        if anomaly_score > 0.3:
            behavior.is_anomaly = True
            behavior.anomaly_score = anomaly_score
            behavior.anomaly_reasons = anomaly_reasons
            behavior.save()
            
            # Create security incident for high-risk anomalies
            if anomaly_score > 0.6:
                SecurityIncidentService.create_incident(
                    'anomaly_detected', 'high', behavior.user, behavior.ip_address,
                    f"High-risk anomaly detected: {', '.join(anomaly_reasons)}"
                )


class RiskAssessmentService:
    """Risk assessment and scoring"""
    
    @staticmethod
    def calculate_session_risk(user, ip_address, location_data):
        """Calculate risk score for a session"""
        risk_score = 0
        
        # Check threat intelligence
        threat = ThreatIntelligenceService.check_ip_reputation(ip_address)
        if threat:
            risk_score += min(threat.threat_score, 50)
        
        # Check for new location
        recent_sessions = UserSession.objects.filter(
            user=user,
            created_at__gte=timezone.now() - timedelta(days=30)
        )
        
        if recent_sessions.exists():
            known_countries = set(recent_sessions.values_list('location_country', flat=True))
            if location_data.get('country') and location_data['country'] not in known_countries:
                risk_score += 20
        
        # Check for recent anomalies
        recent_anomalies = UserBehavior.objects.filter(
            user=user,
            is_anomaly=True,
            timestamp__gte=timezone.now() - timedelta(days=7)
        ).count()
        
        risk_score += min(recent_anomalies * 10, 30)
        
        return min(risk_score, 100)


class SecurityIncidentService:
    """Security incident management"""
    
    @staticmethod
    def create_incident(incident_type, severity, user=None, ip_address=None, description=""):
        """Create a new security incident"""
        incident = SecurityIncident.objects.create(
            incident_type=incident_type,
            severity=severity,
            user=user,
            ip_address=ip_address,
            description=description,
            details={
                'created_by': 'system',
                'auto_generated': True
            }
        )
        
        # Create notification for admin users
        admin_users = User.objects.filter(is_staff=True)
        for admin in admin_users:
            SecurityNotificationService.create_notification(
                admin, 'security_alert', severity,
                f"New {incident_type} incident",
                f"Incident {incident.incident_id}: {description}"
            )
        
        return incident
    
    @staticmethod
    def get_open_incidents():
        """Get all open incidents"""
        return SecurityIncident.objects.filter(
            status__in=['open', 'investigating']
        ).order_by('-created_at')


class SecurityNotificationService:
    """Security notification management"""
    
    @staticmethod
    def create_notification(user, notification_type, priority, title, message, action_url=""):
        """Create a security notification"""
        return SecurityNotification.objects.create(
            user=user,
            notification_type=notification_type,
            priority=priority,
            title=title,
            message=message,
            action_url=action_url
        )
    
    @staticmethod
    def get_unread_notifications(user):
        """Get unread notifications for user"""
        return SecurityNotification.objects.filter(
            user=user,
            is_read=False
        ).order_by('-created_at')


class APIMonitoringService:
    """API usage monitoring and analytics"""
    
    @staticmethod
    def log_api_usage(request, response, start_time):
        """Log API usage"""
        end_time = timezone.now()
        response_time = (end_time - start_time).total_seconds() * 1000
        
        APIUsage.objects.create(
            user=request.user if request.user.is_authenticated else None,
            endpoint=request.path,
            method=request.method,
            ip_address=SessionTrackingService.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            status_code=response.status_code,
            response_time=response_time,
            request_size=len(request.body) if hasattr(request, 'body') else 0,
            response_size=len(response.content) if hasattr(response, 'content') else 0
        )
    
    @staticmethod
    def get_api_stats(hours=24):
        """Get API usage statistics"""
        since = timezone.now() - timedelta(hours=hours)
        
        return {
            'total_calls': APIUsage.objects.filter(timestamp__gte=since).count(),
            'avg_response_time': APIUsage.objects.filter(timestamp__gte=since).aggregate(
                avg=Avg('response_time')
            )['avg'] or 0,
            'error_rate': APIUsage.objects.filter(
                timestamp__gte=since,
                status_code__gte=400
            ).count(),
            'top_endpoints': APIUsage.objects.filter(timestamp__gte=since).values('endpoint').annotate(
                count=Count('endpoint')
            ).order_by('-count')[:10]
        }


class ComplianceService:
    """Compliance reporting and monitoring"""
    
    @staticmethod
    def generate_compliance_report(report_type, start_date, end_date, user):
        """Generate compliance report"""
        findings = []
        recommendations = []
        score = 100.0
        
        # GDPR compliance checks
        if report_type == 'gdpr':
            # Check for data retention policies
            old_logs = MFALog.objects.filter(
                created_at__lt=timezone.now() - timedelta(days=365)
            ).count()
            
            if old_logs > 0:
                findings.append({
                    'type': 'data_retention',
                    'severity': 'medium',
                    'description': f'{old_logs} log entries older than 1 year found'
                })
                recommendations.append('Implement automated data retention policies')
                score -= 10
        
        # Create report
        report = ComplianceReport.objects.create(
            report_type=report_type,
            report_period_start=start_date,
            report_period_end=end_date,
            compliance_score=score,
            findings=findings,
            recommendations=recommendations,
            generated_by=user
        )
        
        return report
