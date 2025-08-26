"""Security middleware for real-time monitoring and tracking"""
from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from django.contrib.auth.models import AnonymousUser
from .security_services import (
    SessionTrackingService, UserBehaviorService, APIMonitoringService,
    ThreatIntelligenceService, SecurityIncidentService
)
import logging

logger = logging.getLogger(__name__)


class SecurityTrackingMiddleware(MiddlewareMixin):
    """Middleware to track user sessions, behavior, and API usage"""
    
    def process_request(self, request):
        """Process incoming requests for security tracking"""
        self.start_time = timezone.now()
        
        # Track API usage for authenticated requests
        if request.user.is_authenticated:
            # Update session tracking
            try:
                SessionTrackingService.create_session(request.user, request)
            except Exception as e:
                logger.error(f"Session tracking failed: {e}")
        
        # Check for threat IPs
        ip_address = SessionTrackingService.get_client_ip(request)
        if ThreatIntelligenceService.is_threat_ip(ip_address):
            # Log security incident
            SecurityIncidentService.create_incident(
                'threat_detected', 'high', request.user if request.user.is_authenticated else None,
                ip_address, f"Request from known threat IP: {ip_address}"
            )
    
    def process_response(self, request, response):
        """Process responses for API monitoring"""
        # Log API usage
        try:
            APIMonitoringService.log_api_usage(request, response, self.start_time)
        except Exception as e:
            logger.error(f"API monitoring failed: {e}")
        
        return response


class BehaviorTrackingMiddleware(MiddlewareMixin):
    """Middleware to track user behavior patterns"""
    
    def process_view(self, request, view_func, view_args, view_kwargs):
        """Track user behavior based on view access"""
        if request.user.is_authenticated and not isinstance(request.user, AnonymousUser):
            # Determine action based on view
            action = self.get_action_from_view(view_func, request)
            
            if action:
                try:
                    UserBehaviorService.log_behavior(request.user, action, request)
                except Exception as e:
                    logger.error(f"Behavior tracking failed: {e}")
    
    def get_action_from_view(self, view_func, request):
        """Determine action type from view function"""
        view_name = getattr(view_func, '__name__', '')
        
        # Map view names to actions
        action_mapping = {
            'login': 'login',
            'logout': 'logout',
            'setup_totp': 'mfa_setup',
            'setup_sms': 'mfa_setup',
            'setup_passkey': 'mfa_setup',
            'verify_totp': 'mfa_verify',
            'verify_sms': 'mfa_verify',
            'verify_email': 'mfa_verify',
            'admin_dashboard': 'admin_access',
            'users_list': 'admin_access',
            'user_detail': 'admin_access',
        }
        
        # Check for admin views
        if 'admin' in view_name:
            return 'admin_access'
        
        return action_mapping.get(view_name, 'page_view')
