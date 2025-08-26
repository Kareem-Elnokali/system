"""Forms used by the MFA app
Contains small forms for verifying factors (TOTP, email OTP, SMS),
backup-code login, re-authentication (sudo mode), and a customized
signup/password reset flow.
"""
from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import PasswordResetForm as DjangoPasswordResetForm
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
UserModel = get_user_model()
class CustomPasswordResetForm(DjangoPasswordResetForm):
    def save(self, domain_override=None, subject_template_name=None, email_template_name=None, use_https=False, token_generator=None, from_email=None, request=None, html_email_template_name=None, extra_email_context=None):
        """
        Generates a one-use only link for resetting password and sends to the user.
        This custom version prevents superusers from resetting their password and
        does not reveal whether an email is in the system.
        """
        email = (self.cleaned_data["email"] or "").strip()
        active_users = self.get_users(email)
        display_key = None
        for user in active_users:
            if not user.has_usable_password():
                continue
            ctx = dict(extra_email_context or {})
            try:
                user_key = getattr(getattr(user, 'mfa_profile', None), 'safety_key', '')
            except Exception:
                user_key = ''
            ctx.setdefault('site_name', getattr(settings, 'SITE_NAME', 'MySite'))
            super().save(
                domain_override=domain_override,
                subject_template_name=subject_template_name,
                email_template_name=email_template_name,
                use_https=use_https,
                token_generator=token_generator,
                from_email=from_email,
                request=request,
                html_email_template_name=html_email_template_name,
                extra_email_context=ctx,
            )
            if display_key is None and user_key:
                display_key = user_key
        try:
            if request is not None:
                if not display_key and email:
                    import hashlib
                    hexd = hashlib.sha256(email.lower().encode('utf-8')).hexdigest()
                    display_key = hexd[:8]
                request.session['password_reset_display_safety'] = display_key or getattr(settings, 'SAFETY_PHRASE', '')
                request.session.save()
        except Exception:
            pass
    def get_users(self, email):
        """Given an email, return matching user(s) who should receive a reset.
        This method is overridden to only return active, non-superuser users.
        """
        return UserModel._default_manager.filter(**{
            '%s__iexact' % UserModel.get_email_field_name(): email,
            'is_active': True,
            'is_superuser': False,
        })
class TOTPVerifyForm(forms.Form):
    """Collect a 6–8 digit authenticator code from the user."""
    code = forms.CharField(
        label='Authenticator code',
        max_length=8,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter 6-digit code'}),
    )
class BackupCodeLoginForm(forms.Form):
    """Allow login with a single-use backup code plus identifier."""
    username = forms.CharField(
        label='Username or Email',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter your username or email'}),
    )
    code = forms.CharField(
        label='Backup code',
        max_length=16,
        widget=forms.TextInput(attrs={
            'class': 'form-control font-monospace',
            'placeholder': 'XXXX-XXXX',
            'autocomplete': 'one-time-code',
            'inputmode': 'text',
            'spellcheck': 'false',
            'autocapitalize': 'characters',
        }),
    )
class EmailOTPForm(forms.Form):
    """Collect a 6-digit email OTP from the user."""
    code = forms.CharField(
        label='Email code',
        max_length=6,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter 6-digit code'}),
    )
    def clean_code(self):
        code = (self.cleaned_data.get('code') or '').strip()
        if not (len(code) == 6 and code.isdigit()):
            raise ValidationError('Enter a valid 6-digit code.')
        if len(set(code)) == 1:
            raise ValidationError('This code is not allowed. Please enter a different code.')
        return code
class PhoneNumberForm(forms.Form):
    """Collect a phone number to use for SMS OTP in E.164 format."""
    phone_number = forms.CharField(
        label="Phone Number",
        widget=forms.TextInput(attrs={'placeholder': '+11234567890', 'autocomplete': 'tel'}),
    )
    def clean_phone_number(self):
        phone_number = self.cleaned_data.get('phone_number')
        if not phone_number.startswith('+'):
            raise forms.ValidationError("Phone number must start with a country code (e.g., +1).")
        if not phone_number[1:].isdigit():
            raise forms.ValidationError("Phone number must only contain digits after the initial '+'.")
        return phone_number
class SMSVerifyForm(forms.Form):
    """Collect a 6-digit code sent via SMS."""
    code = forms.CharField(
        label="Verification Code",
        widget=forms.TextInput(attrs={'placeholder': '123456', 'autocomplete': 'one-time-code'}),
        max_length=6,
    )
class ReAuthenticationForm(forms.Form):
    """
    A simple form for re-authenticating a user by asking for their password.
    """
    password = forms.CharField(widget=forms.PasswordInput, label="Password")
    def __init__(self, request, *args, **kwargs):
        self.request = request
        super().__init__(*args, **kwargs)
    def clean_password(self):
        password = self.cleaned_data.get('password')
        if not self.request.user.check_password(password):
            raise forms.ValidationError("Incorrect password. Please try again.")
        return password
class CustomSignupForm(UserCreationForm):
    """User signup with required, unique email and Bootstrap widgets."""
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email address'
        })
    )
    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')
        widgets = {
            'username': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Choose a username'
            }),
        }
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['password1'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Create a password'
        })
        self.fields['password2'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Confirm your password'
        })
    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
        return user
    def clean_email(self):
        """Ensure email is unique (case-insensitive) and trimmed."""
        email = self.cleaned_data.get('email', '')
        email = (email or '').strip().lower()
        if not email:
            raise ValidationError('Email is required.')
        if User.objects.filter(email__iexact=email).exists():
            raise ValidationError('An account with this email already exists.')
        try:
            from allauth.socialaccount.models import SocialAccount
            if SocialAccount.objects.filter(user__email__iexact=email, provider='google').exists():
                raise ValidationError('This email is registered via Google. Please sign in with Google instead.')
        except Exception:
            pass
        return email