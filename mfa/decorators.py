"""MFA decorators
These wrappers enforce preconditions around MFA flows:
- `mfa_login_required`: ensure there's a pending MFA user in session.
- `reauth_required`: require recent password confirmation (sudo mode).
- `staff_mfa_required`: ensure admin access is both authenticated and MFA-verified.
"""
from functools import wraps
from django.shortcuts import redirect
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from datetime import timedelta
from django.contrib import messages
from urllib.parse import urlencode
from django.contrib.auth.models import Group
from .flow import SESSION_USER_ID
def mfa_login_required(view_func):
    """
    Decorator for views that require a pending MFA user session.
    If the user is not in the process of an MFA flow, redirect to login.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if SESSION_USER_ID not in request.session:
            messages.error(request, 'Your session has expired. Please log in again.')
            return redirect(reverse_lazy('mfa:login'))
        return view_func(request, *args, **kwargs)
    return _wrapped_view
def reauth_required(view_func):
    """
    A decorator for views that require recent re-authentication (sudo mode).
    Checks for a session timestamp to ensure the user has confirmed their
    password recently. If not, it redirects them to a re-authentication page,
    preserving their original destination to be returned to upon success.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        reauth_at_str = request.session.get('reauth_at')
        if reauth_at_str:
            reauth_at = timezone.datetime.fromisoformat(reauth_at_str)
            if timezone.now() - reauth_at < timedelta(minutes=10):
                return view_func(request, *args, **kwargs)
        reauth_url = reverse('mfa:reauth')
        next_url = request.get_full_path()
        redirect_url = f"{reauth_url}?{urlencode({'next': next_url})}"
        messages.info(request, 'Please confirm your password to access this page.')
        return redirect(redirect_url)
    return _wrapped_view
def staff_mfa_required(view_func):
    """
    Decorator for views that checks that the user is a logged-in superuser
    and has completed a recent MFA check.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated or not request.user.is_superuser:
            return redirect(reverse_lazy('mfa:admin_login'))
        mfa_verified_at_str = request.session.get('mfa_admin_verified_at')
        if not mfa_verified_at_str:
            return redirect(reverse_lazy('mfa:admin_login'))
        try:
            mfa_verified_at = timezone.datetime.fromisoformat(mfa_verified_at_str)
            if timezone.now() - mfa_verified_at > timedelta(minutes=30):
                messages.info(request, "Your admin session has expired. Please log in again for security.")
                return redirect(reverse_lazy('mfa:admin_login'))
            request.session['mfa_admin_verified_at'] = timezone.now().isoformat()
        except (ValueError, TypeError):
            return redirect(reverse_lazy('mfa:admin_login'))
        return view_func(request, *args, **kwargs)
    return _wrapped_view

def admin_required(view_func):
    """
    Decorator for admin views that require superuser access.
    Alias for staff_mfa_required for consistency.
    """
    return staff_mfa_required(view_func)

# --- Least-privilege admin access helpers ---
def _mfa_recent_enough(request, key='mfa_admin_verified_at', minutes=30):
    ts = request.session.get(key)
    if not ts:
        return False
    try:
        verified_at = timezone.datetime.fromisoformat(ts)
        if timezone.now() - verified_at <= timedelta(minutes=minutes):
            # refresh sliding window
            request.session[key] = timezone.now().isoformat()
            return True
    except (ValueError, TypeError):
        return False
    return False

def admin_mfa_required(view_func):
    """Allow any authenticated staff or superuser with recent admin-MFA session."""
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        user = request.user
        if not user.is_authenticated or not (user.is_staff or user.is_superuser):
            return redirect(reverse_lazy('mfa:admin_login'))
        if not _mfa_recent_enough(request):
            messages.info(request, "Your admin session has expired. Please log in again for security.")
            return redirect(reverse_lazy('mfa:admin_login'))
        return view_func(request, *args, **kwargs)
    return _wrapped

def _has_any_group(user, group_names):
    if not group_names:
        return True
    user_groups = set(user.groups.values_list('name', flat=True))
    return any(g in user_groups for g in group_names)

def admin_groups_required(*group_names):
    """Require admin MFA and membership in any of the given groups, or superuser."""
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            user = request.user
            if not user.is_authenticated or not (user.is_staff or user.is_superuser):
                return redirect(reverse_lazy('mfa:admin_login'))
            if not _mfa_recent_enough(request):
                messages.info(request, "Your admin session has expired. Please log in again for security.")
                return redirect(reverse_lazy('mfa:admin_login'))
            if user.is_superuser:
                return view_func(request, *args, **kwargs)
            if not _has_any_group(user, group_names):
                messages.error(request, "You don't have permission to access this page.")
                return redirect(reverse_lazy('mfa:admin_dashboard'))
            return view_func(request, *args, **kwargs)
        return _wrapped
    return decorator

def admin_perms_required(*perm_codenames):
    """Require admin MFA and specific Django permissions (app_label.codename), or superuser."""
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            user = request.user
            if not user.is_authenticated or not (user.is_staff or user.is_superuser):
                return redirect(reverse_lazy('mfa:admin_login'))
            if not _mfa_recent_enough(request):
                messages.info(request, "Your admin session has expired. Please log in again for security.")
                return redirect(reverse_lazy('mfa:admin_login'))
            if user.is_superuser or (not perm_codenames) or user.has_perms(perm_codenames):
                return view_func(request, *args, **kwargs)
            messages.error(request, "You don't have permission to access this page.")
            return redirect(reverse_lazy('mfa:admin_dashboard'))
        return _wrapped
    return decorator
