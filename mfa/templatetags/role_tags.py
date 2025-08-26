from django import template

register = template.Library()

@register.filter(name='has_group')
def has_group(user, group_name: str) -> bool:
    try:
        return user.is_authenticated and (user.is_superuser or user.groups.filter(name=group_name).exists())
    except Exception:
        return False

@register.filter(name='has_any_group')
def has_any_group(user, group_names: str) -> bool:
    """
    Usage: {% if request.user|has_any_group:"Security Admin,Analyst" %}
    """
    if not user.is_authenticated:
        return False
    if user.is_superuser:
        return True
    names = [g.strip() for g in (group_names or '').split(',') if g.strip()]
    if not names:
        return True
    return user.groups.filter(name__in=names).exists()
