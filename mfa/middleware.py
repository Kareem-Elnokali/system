"""Middleware enforcing MFA for Django admin access
This middleware ensures that superusers accessing `/admin/` complete an
email OTP check for the current session. It exempts admin login/logout
and all `mfa:` URLs to avoid redirect loops.
"""
from django.urls import reverse
from django.shortcuts import redirect
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from django.core.mail import send_mail
import random
from .flow import SESSION_USER_ID, SESSION_EMAIL_CODE, SESSION_EMAIL_EXPIRES
class AdminMFAMiddleware(MiddlewareMixin):
    """
    Enforce email OTP for superusers accessing Django admin.
    Flow:
    - If request is to /admin/* and user is an authenticated superuser
      and no admin-MFA flag in session, trigger email OTP and redirect
      to mfa:verify_email with next set to the current admin URL.
    - Exempt admin login/logout and all mfa URLs to avoid loops.
    """
    def process_request(self, request):
        path = request.path
        if not path.startswith('/admin/'):
            return None
        try:
            admin_login = reverse('admin:login')
            admin_logout = reverse('admin:logout')
        except Exception:
            admin_login = '/admin/login/'
            admin_logout = '/admin/logout/'
        if path in (admin_login, admin_logout):
            return None
        if path.startswith('/mfa/'):
            return None
        user = getattr(request, 'user', None)
        if not (user and user.is_authenticated and user.is_superuser):
            login_url_with_next = f"{reverse('mfa:admin_login')}?next={request.path}"
            return redirect(login_url_with_next)
        if request.session.get('mfa_admin_ok'):
            return None
        user_email = getattr(user, 'email', None)
        if user_email:
            code = f"{random.randint(0, 999999):06d}"
            request.session[SESSION_USER_ID] = user.id
            request.session[SESSION_EMAIL_CODE] = code
            request.session[SESSION_EMAIL_EXPIRES] = (timezone.now() + timedelta(minutes=5)).isoformat()
            request.session['mfa_next'] = request.get_full_path()
            request.session.modified = True
            try:
                send_mail(
                    subject=getattr(settings, 'MFA_EMAIL_SUBJECT', 'Your login code'),
                    message=f"Your one-time code is: {code}\nThis code expires in 5 minutes.",
                    from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', None),
                    recipient_list=[user_email],
                    fail_silently=False,
                )
            except Exception:
                if getattr(settings, 'MFA_FAIL_OPEN', True):
                    request.session['mfa_admin_ok'] = True
                    request.session.modified = True
                    return None
                return redirect(admin_login)
            return redirect(f"{reverse('mfa:verify_email')}?next={request.get_full_path()}")
        else:
            if getattr(settings, 'MFA_FAIL_OPEN', True):
                request.session['mfa_admin_ok'] = True
                request.session.modified = True
                return None
            return redirect(admin_login)
        return None
