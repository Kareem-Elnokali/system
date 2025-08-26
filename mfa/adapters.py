from __future__ import annotations
import logging
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.utils import generate_unique_username
from django.contrib.auth import get_user_model
logger = logging.getLogger(__name__)
class SocialAdapter(DefaultSocialAccountAdapter):
    """Force auto-signup for social logins and ensure a username is set.
    This avoids the intermediate `/accounts/3rdparty/signup/` form.
    """
    def is_auto_signup_allowed(self, request, sociallogin):
        logger.debug('SocialAdapter.is_auto_signup_allowed provider=%s email=%s',
                     getattr(getattr(sociallogin, 'account', None), 'provider', None),
                     getattr(getattr(sociallogin, 'user', None), 'email', None))
        return True
    def populate_user(self, request, sociallogin, data):
        user = super().populate_user(request, sociallogin, data)
        if not getattr(user, 'username', None):
            base = (
                (data.get('email') or '').split('@')[0]
                or data.get('username')
                or data.get('name')
                or data.get('given_name')
                or 'user'
            )
            user.username = generate_unique_username([base])
        logger.debug('SocialAdapter.populate_user email=%s username=%s', getattr(user, 'email', None), getattr(user, 'username', None))
        return user
    def pre_social_login(self, request, sociallogin):
        """If a user with the same verified email exists, attach and login.
        This prevents the intermediate /accounts/3rdparty/signup/ page.
        """
        if sociallogin.is_existing:
            logger.debug('pre_social_login: social account already linked, skipping connect')
            return
        user = sociallogin.user
        email = (getattr(user, 'email', '') or '').strip().lower()
        if not email:
            logger.debug('pre_social_login: no email from provider; cannot auto-link')
            return
        User = get_user_model()
        try:
            existing = User.objects.filter(email__iexact=email).first()
        except Exception:
            existing = None
        if existing:
            sociallogin.connect(request, existing)
            logger.debug('pre_social_login: connected social account to existing user id=%s', getattr(existing, 'id', None))
        else:
            logger.debug('pre_social_login: no existing user with email=%s; allauth may show 3rdparty signup', email)
