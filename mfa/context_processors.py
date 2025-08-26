from django.conf import settings
def brand_colors(request):
    safety = getattr(settings, "SAFETY_PHRASE", "")
    return {
        "brand_color": getattr(settings, "BRAND_COLOR", "#55833d"),
        "brand_color_hover": getattr(settings, "BRAND_COLOR_HOVER", "#466d33"),
        "brand_color_weak": getattr(settings, "BRAND_COLOR_WEAK", "#55833d5b"),
        "site_name": getattr(settings, "SITE_NAME", "MySite"),
        "safety_phrase": safety,
    }

def role_flags(request):
    """Expose basic RBAC role flags to all templates."""
    user = getattr(request, 'user', None)
    if not user or not getattr(user, 'is_authenticated', False):
        return {
            'is_security_admin': False,
            'is_analyst': False,
            'is_compliance': False,
            'is_support': False,
            'is_staff_user': False,
            'is_superuser_user': False,
        }
    # Group-based checks
    in_group = user.groups.filter
    return {
        'is_security_admin': in_group(name='Security Admin').exists() or user.is_superuser,
        'is_analyst': in_group(name='Analyst').exists(),
        'is_compliance': in_group(name='Compliance').exists(),
        'is_support': in_group(name='Support').exists(),
        'is_staff_user': bool(getattr(user, 'is_staff', False)),
        'is_superuser_user': bool(getattr(user, 'is_superuser', False)),
    }
