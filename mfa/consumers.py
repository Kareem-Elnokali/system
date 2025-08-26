import json
import asyncio
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.core.cache import cache
from django.contrib.sessions.models import Session
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db.models import Count, Q
from datetime import timedelta
import json
import time
from .models import MFALog, MFADevice

User = get_user_model()

class RealtimeMonitoringConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Debug connection attempt
        user = self.scope.get('user')
        print(f"WebSocket connection attempt from user: {user}")
        print(f"User authenticated: {user.is_authenticated if user and hasattr(user, 'is_authenticated') else False}")
        print(f"User is staff: {getattr(user, 'is_staff', False) if user else False}")
        
        # Accept connection first, then check authentication
        await self.accept()
        
        # Check if user is staff (allow connection but send error if not authenticated)
        if not user or not user.is_authenticated or not getattr(user, 'is_staff', False):
            print("WebSocket connection: User not authenticated or not staff")
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Authentication required. Please log in as an admin user.'
            }))
            return
        
        # Join monitoring group
        self.room_group_name = 'admin_monitoring'
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        print(f"WebSocket connection accepted for user: {user.username}")
        
        # Send initial data
        try:
            await self.send_system_health()
            await self.send_recent_events()
            print("Initial data sent successfully")
            
            # Start periodic updates
            self.update_task = asyncio.create_task(self.periodic_updates())
        except Exception as e:
            print(f"Error sending initial data: {e}")
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': f'Error loading initial data: {str(e)}'
            }))

    async def disconnect(self, close_code):
        # Stop periodic updates
        if hasattr(self, 'update_task'):
            self.update_task.cancel()
        
        # Leave room group
        if hasattr(self, 'room_group_name'):
            await self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
            )
        print(f"WebSocket disconnected with code: {close_code}")

    async def receive(self, text_data):
        data = json.loads(text_data)
        message_type = data.get('type')
        
        if message_type == 'get_system_health':
            await self.send_system_health()
        elif message_type == 'get_recent_events':
            await self.send_recent_events()

    # Receive message from room group
    async def mfa_event(self, event):
        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'type': 'mfa_event',
            'event': event['event_data']
        }))

    async def system_health(self, event):
        await self.send(text_data=json.dumps({
            'type': 'system_health',
            'data': event['data']
        }))

    @database_sync_to_async
    def get_system_health_data(self):
        from django.db import connection
        from django.core.cache import cache
        
        # Database health
        db_healthy = True
        db_query_time = 0
        try:
            import time
            start = time.time()
            with connection.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM django_session WHERE expire_date > %s", [timezone.now()])
                active_sessions = cursor.fetchone()[0]
            db_query_time = int((time.time() - start) * 1000)  # ms
        except Exception:
            db_healthy = False
            active_sessions = 0
            db_query_time = 0

        # Cache health
        cache_healthy = True
        try:
            cache.set('health_check', 'ok', 1)
            cache_healthy = cache.get('health_check') == 'ok'
        except Exception:
            cache_healthy = False

        # Get threat metrics
        now = timezone.now()
        last_hour = now - timedelta(hours=1)
        
        failed_logins = MFALog.objects.filter(
            created_at__gte=last_hour,
            event__in=['login_failure', 'email_verify_failure', 'totp_verify_failure']
        ).count()
        
        # Get unique IPs with failures
        suspicious_ips = MFALog.objects.filter(
            created_at__gte=last_hour,
            event__in=['login_failure', 'email_verify_failure', 'totp_verify_failure']
        ).values('ip_address').distinct().count()
        
        return {
            'db_healthy': db_healthy,
            'db_query_time': db_query_time,
            'cache_healthy': cache_healthy,
            'active_sessions': active_sessions,
            'failed_logins': failed_logins,
            'suspicious_ips': suspicious_ips,
            'timestamp': timezone.now().isoformat()
        }

    @database_sync_to_async
    def get_recent_events_data(self):
        # Get last 20 MFA events ordered by creation time (newest first)
        recent_logs = MFALog.objects.select_related('user').order_by('-created_at')[:20]
        # Reverse to show oldest first in the feed (chronological order)
        recent_logs = list(reversed(recent_logs))
        
        events = []
        for log in recent_logs:
            # Determine event type for styling based on event name
            if 'fail' in log.event or 'failure' in log.event or 'error' in log.event:
                event_type = 'failure'
            elif 'success' in log.event or 'verify_success' in log.event or 'login_success' in log.event:
                event_type = 'success'
            elif 'rate_limit' in log.event or 'lockout' in log.event:
                event_type = 'warning'
            else:
                event_type = 'success'  # Default fallback
            
            # Get method from log.method field first, then fallback to event parsing
            method = log.method or 'Unknown'
            if method == 'password':
                # For password events, determine MFA method from event name
                if 'email' in log.event:
                    method = 'Email OTP'
                elif 'totp' in log.event:
                    method = 'TOTP'
                elif 'passkey' in log.event:
                    method = 'Passkey'
                elif 'backup' in log.event:
                    method = 'Backup Code'
                elif 'sms' in log.event:
                    method = 'SMS'
                else:
                    method = 'Login'
            elif method == 'email':
                method = 'Email OTP'
            elif method == 'totp':
                method = 'TOTP'
            elif method == 'backup_code':
                method = 'Backup Code'
            
            events.append({
                'type': event_type,
                'event': log.event,
                'user': log.user.username if log.user else 'Unknown',
                'method': method,
                'ip': log.ip_address or 'Unknown',
                'timestamp': log.created_at.isoformat(),
                'details': log.details or ''
            })
        
        return events

    async def send_system_health(self):
        """Send current system health data with real metrics"""
        try:
            health_data = await self.get_system_health_data()
            
            await self.send(text_data=json.dumps({
                'type': 'system_health',
                'data': health_data
            }))
            
        except Exception as e:
            print(f"Error sending system health: {e}")

    @database_sync_to_async
    def get_system_health_data(self):
        """Get real system health data from database"""
        from django.db import connection
        
        # Database health
        db_healthy = True
        db_query_time = 0
        try:
            import time
            start = time.time()
            with connection.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM django_session WHERE expire_date > %s", [timezone.now()])
                active_sessions = cursor.fetchone()[0]
            db_query_time = int((time.time() - start) * 1000)  # ms
        except Exception:
            db_healthy = False
            active_sessions = 0
            db_query_time = 0

        # Cache health
        cache_healthy = True
        try:
            cache.set('health_check', 'ok', 1)
            cache_healthy = cache.get('health_check') == 'ok'
        except Exception:
            cache_healthy = False

        # Get threat metrics
        now = timezone.now()
        last_hour = now - timedelta(hours=1)
        
        failed_logins = MFALog.objects.filter(
            created_at__gte=last_hour,
            event__in=['login_failure', 'email_verify_failure', 'totp_verify_failure']
        ).count()
        
        # Get unique IPs with failures
        suspicious_ips = MFALog.objects.filter(
            created_at__gte=last_hour,
            event__in=['login_failure', 'email_verify_failure', 'totp_verify_failure']
        ).values('ip_address').distinct().count()
        
        # Get events today
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        events_today = MFALog.objects.filter(created_at__gte=today_start).count()
        
        # Get unique users today
        unique_users_today = MFALog.objects.filter(
            created_at__gte=today_start
        ).values('user').distinct().count()
        
        # Get success rate
        success_events = ['email_verify_success', 'totp_verify_success', 'backup_code_used']
        failure_events = ['email_verify_failure', 'totp_verify_failure']
        
        successes_hour = MFALog.objects.filter(
            created_at__gte=last_hour,
            event__in=success_events
        ).count()
        
        failures_hour = MFALog.objects.filter(
            created_at__gte=last_hour,
            event__in=failure_events
        ).count()
        
        total_hour = successes_hour + failures_hour
        success_rate = (successes_hour / total_hour * 100) if total_hour > 0 else 100
        
        # Get geographic data from recent events
        geographic_data = {}
        recent_logs = MFALog.objects.filter(
            created_at__gte=last_hour
        ).values('ip_address')[:50]
        
        for log in recent_logs:
            ip = log.get('ip_address', '127.0.0.1')
            location = self.get_location_from_ip(ip)
            geographic_data[location] = geographic_data.get(location, 0) + 1

        return {
            'db_healthy': db_healthy,
            'db_query_time': db_query_time,
            'cache_healthy': cache_healthy,
            'active_sessions': active_sessions,
            'failed_logins': failed_logins,
            'suspicious_ips': suspicious_ips,
            'events_today': events_today,
            'unique_users_today': unique_users_today,
            'success_rate': round(success_rate, 1),
            'geographic_data': geographic_data,
            'timestamp': timezone.now().isoformat()
        }

    async def send_recent_events(self):
        """Send recent MFA events with real data"""
        try:
            events_data = await self.get_recent_events_data()
            
            await self.send(text_data=json.dumps({
                'type': 'recent_events',
                'data': events_data
            }))
            
        except Exception as e:
            print(f"Error sending recent events: {e}")

    def get_location_from_ip(self, ip_address):
        """Simple IP to location mapping (placeholder)"""
        if not ip_address or ip_address == '127.0.0.1':
            return 'Local'
        # Simple approximation based on IP ranges
        if ip_address.startswith('192.168.') or ip_address.startswith('10.'):
            return 'Internal Network'
        return 'External'

    async def periodic_updates(self):
        """Send periodic updates every 30 seconds"""
        while True:
            try:
                await asyncio.sleep(30)
                await self.send_system_health()
                await self.send_recent_events()
            except Exception as e:
                print(f"Error in periodic updates: {e}")
                break

    async def disconnect(self, close_code):
        """Handle WebSocket disconnect"""
        if hasattr(self, 'room_group_name'):
            await self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
            )
        
        if hasattr(self, 'update_task'):
            self.update_task.cancel()
    
    async def periodic_updates(self):
        """Send periodic system health updates every 30 seconds"""
        try:
            while True:
                await asyncio.sleep(30)  # Update every 30 seconds
                await self.send_system_health()
                
                # Send a heartbeat to keep connection alive
                await self.send(text_data=json.dumps({
                    'type': 'heartbeat',
                    'timestamp': timezone.now().isoformat()
                }))
        except asyncio.CancelledError:
            print("Periodic updates cancelled")
        except Exception as e:
            print(f"Error in periodic updates: {e}")
    
    def get_location_from_ip(self, ip_address):
        """Get approximate location from IP address (simplified)"""
        if not ip_address:
            return 'Unknown'
        
        # Check if it's a local/private IP
        if ip_address.startswith(('127.', '192.168.', '10.', '172.')):
            return 'Local Network'
        
        # For demo purposes, return some sample locations
        # In production, you'd use a real IP geolocation service
        sample_locations = [
            'New York, US', 'London, UK', 'Tokyo, JP', 
            'Sydney, AU', 'Berlin, DE', 'Toronto, CA'
        ]
        
        # Use IP hash to consistently return same location for same IP
        import hashlib
        ip_hash = int(hashlib.md5(ip_address.encode()).hexdigest(), 16)
        return sample_locations[ip_hash % len(sample_locations)]
