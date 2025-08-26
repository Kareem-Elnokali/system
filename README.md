# 🔐 Enterprise MFA Admin System

A comprehensive, enterprise-grade Multi-Factor Authentication (MFA) system with advanced admin features, real-time monitoring, threat intelligence, and compliance reporting. Built with Django and designed for scalability, security, and enterprise requirements.

## 🌟 Key Features

### Core MFA Capabilities
- **Multi-Factor Authentication**: Email OTP, TOTP (authenticator apps), Passkeys (WebAuthn/FIDO2), SMS OTP, Backup Codes
- **Advanced Security**: Rate limiting, IP blocking, device fingerprinting, risk scoring
- **Session Management**: Remember me options, secure session handling, automatic logout
- **Admin Protection**: Dedicated admin MFA with email OTP verification

### Enterprise Admin Features
- **Real-time Monitoring**: Live authentication dashboard with WebSocket updates
- **User Behavior Analytics**: AI-powered anomaly detection and risk assessment
- **Security Policy Engine**: Automated policy enforcement and compliance monitoring
- **Threat Intelligence**: Real-time threat feeds with automated response capabilities
- **Organization Management**: Multi-tenant support with hierarchical access control
- **Backup & Recovery**: Comprehensive disaster recovery and data protection
- **API Management**: RESTful API with rate limiting, webhooks, and documentation
- **Enterprise Reporting**: Compliance reports (SOX, GDPR, HIPAA, ISO 27001), executive dashboards

### Security & Compliance
- **Audit Logging**: Comprehensive security event tracking with export capabilities
- **Risk Management**: User risk scoring, automated restrictions, security alerts
- **Compliance Dashboard**: Real-time compliance status for major frameworks
- **Data Protection**: Encrypted storage, secure backups, GDPR compliance
- **Threat Detection**: Advanced threat intelligence with automated blocking

## 🚀 Quick Start

### Installation

---

## Quick Start (Copy-Paste Checklist)

1) Install packages: `pip install django django-allauth passkeys [firebase-admin] [keyring]`.

2) Settings (`mysite/settings.py`):
   - Add apps to `INSTALLED_APPS` (see section 2).
   - Add `AuthenticationMiddleware`, `AccountMiddleware` and our localhost middleware in `DEBUG` (section 5).
   - Set `AUTHENTICATION_BACKENDS` including `passkeys.backend.PasskeyModelBackend` (section 3).
   - Import `from mfa.auth_settings import *` for allauth defaults.
   - Configure `FIDO_SERVER_ID='localhost'` for local dev (section 4).
   - Set `STATIC_URL`, `STATICFILES_DIRS`, `ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS` (sections 6 and 8).
   - Email SMTP (section 9). Optional: Firebase SMS, CAPTCHA (sections 10–11).

3) URLs (`mysite/urls.py`): include `accounts/`, `mfa/`, and passkeys overrides (section 7).

4) Templates: ensure `templates/` in `TEMPLATES[...]['DIRS']` and context processors (section 2). Copy or adapt pages from `mfa/templates/`.

5) Migrate DB: `python manage.py makemigrations && python manage.py migrate` (section 12).

6) Configure Google login (optional but recommended): Create OAuth client, add `SocialApp` in Django admin, map to your `Site` (see section 21 below).

7) Configure CAPTCHA if used: set keys, add site key to template, call server-side verifier (section 22).

8) Run `python manage.py runserver 8000`. Use one host only (prefer `http://localhost:8000`).

9) Test flows: login -> method picker -> Email/TOTP/Passkey/Backup Codes -> Profile.

---
## Features
- Email one-time codes (+ admin OTP for `/admin/`)
- TOTP (RFC 6238) authenticator app pairing and verification
- Passkeys (WebAuthn/FIDO2) authentication via `passkeys`
- Single-use Backup Codes (12 codes, normalized and hashed)
- Optional SMS OTP (dev helper or Firebase backend)
- Google reCAPTCHA v2 or Cloudflare Turnstile (server-side verify)
- MFA method picker, Security Hub, and profile page
- Comprehensive session handling and host consistency for WebAuthn

---

## Requirements
- Python 3.11+
- Django 5.2+
- Installed apps: `mfa`, `passkeys`, `django-allauth` (+ Google provider if used)

---

## 1) Install packages

Add these to your environment (pin versions as you prefer):

```bash
pip install django django-allauth passkeys
```

If you plan to use Firebase SMS:
```bash
pip install firebase-admin
```

If you plan to use keyring for secure local storage of reCAPTCHA keys (Windows Credential Manager):
```bash
pip install keyring
```

---

## 2) Add apps to `INSTALLED_APPS`
In your project settings (e.g., `mysite/settings.py`), include:

```python
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'mfa',
    'passkeys',

    # django-allauth
    'django.contrib.sites',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.google',  # optional
]

SITE_ID = 1
```

Templates must include your project `templates/` dir and the request/messages context processors:

```python
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]
```

---

## 3) Authentication backends
Enable `allauth` and the passkeys backend so sessions created by passkeys are recognized:

```python
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
    'passkeys.backend.PasskeyModelBackend',
]
```

We also centralize some allauth settings in `mfa/auth_settings.py`. Import those at the top of your settings:

```python
from mfa.auth_settings import *
```

This provides defaults like:
- `ACCOUNT_USERNAME_REQUIRED = False`
- `SOCIALACCOUNT_AUTO_SIGNUP = True`
- Redirects: `LOGIN_REDIRECT_URL`, `ACCOUNT_SIGNUP_REDIRECT_URL`, `ACCOUNT_LOGOUT_REDIRECT_URL`

Adjust as needed for your site.

---

## 4) FIDO2 / Passkeys configuration
For local development over HTTP, WebAuthn typically supports `http://localhost` only. In this project we set:

```python
FIDO_SERVER_ID = 'localhost'       # RP ID (host only)
FIDO_SERVER_NAME = 'GreenShield MFA'
```

Important: Use a single host consistently (e.g., `http://localhost:8000`). Host switching (e.g., `127.0.0.1` <-> `localhost`) causes browsers not to send session cookies.

Middleware is provided to normalize the host while excluding all `/mfa/` paths to avoid breaking the passkey flow. See middleware notes below.

---

## 5) Middleware
Add `allauth.account.middleware.AccountMiddleware` and our localhost normalization middleware early in the chain in `DEBUG`:

```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

if DEBUG:
    # Ensure it runs first in development
    MIDDLEWARE.insert(0, 'mysite.middleware.LocalhostRedirectMiddleware')
```

`mysite/middleware.py` should define:

```python
class LocalhostRedirectMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from urllib.parse import urlsplit, urlunsplit
        from django.http import HttpResponseRedirect

        host = request.get_host()
        path = request.path
        # Avoid rewriting any /mfa/ path to preserve session + WebAuthn
        if host.startswith('127.0.0.1') and not path.startswith('/mfa/'):
            parts = urlsplit(request.build_absolute_uri())
            netloc = parts.netloc.replace('127.0.0.1', 'localhost')
            new_url = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
            return HttpResponseRedirect(new_url)
        return self.get_response(request)
```

---

## 6) CSRF and allowed hosts
In development, allow both hosts and common proxy ports:

```python
ALLOWED_HOSTS = ['*']
CSRF_TRUSTED_ORIGINS = [
    'http://127.0.0.1:8000',
    'http://127.0.0.1:62847',
    'http://localhost:8000',
    'http://localhost:62847',
]
```

---

## 7) URL configuration
Include the MFA URLs and (optionally) override passkeys auth routes to ensure our wrappers run:

```python
# mysite/urls.py
from django.contrib import admin
from django.urls import path, include
from mfa import views as mfa_views

urlpatterns = [
    path('admin/', admin.site.urls),

    # allauth
    path('accounts/', include('allauth.urls')),

    # MFA
    path('mfa/', include(('mfa.urls', 'mfa'), namespace='mfa')),

    # Passkeys overrides (optional but recommended)
    path('passkeys/auth/begin', mfa_views.passkey_auth_begin, name='passkeys_auth_begin_override'),
    path('passkeys/auth/complete', mfa_views.passkey_auth_complete, name='passkeys_auth_complete_override'),
    path('passkeys/', include(('passkeys.urls', 'passkeys'), namespace='passkeys')),
]
```

### Admin routing (project-level)

This project routes `/admin/` to the custom MFA Admin Dashboard and exposes Django’s built-in admin at `/django-admin/`:

```python
from django.views.generic import RedirectView

urlpatterns = [
    path('admin/', RedirectView.as_view(pattern_name='mfa:admin_dashboard', permanent=False)),
    path('django-admin/', admin.site.urls),
    # ... other routes ...
]
```

Adjust as needed if you prefer to keep Django admin at `/admin/`. The MFA admin dashboard lives at `mfa:admin_dashboard` and the admin login + email OTP flow is under `mfa:admin_login` → `mfa:admin_verify_email`.

---

## 8) Static and templates
Ensure static files are served (in dev) and your `templates/` directory is in `TEMPLATES[...]['DIRS']`.

```python
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
```

---

## 9) Email (for password reset / email OTP)
Provide SMTP settings appropriate for your environment (example shows Gmail SMTP):

```python
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'your_email@example.com'
EMAIL_HOST_PASSWORD = 'app_password_or_secret'

DEFAULT_FROM_EMAIL = EMAIL_HOST_USER
SERVER_EMAIL = EMAIL_HOST_USER
EMAIL_TIMEOUT = 30
```

Change these for production and keep secrets out of source control.

---

## 10) Optional: SMS OTP (Firebase) and dev helper
- Dev helper: When `DEBUG` or `FORCE_DEV_OTP=True`, the app will generate a 6-digit code server-side for SMS flows (printed/logged).
- Firebase Admin SDK (optional) for real phone linking/verification during setup:

```python
FIREBASE_CONFIG = {
    'apiKey': os.getenv('FIREBASE_API_KEY'),
    'authDomain': os.getenv('FIREBASE_AUTH_DOMAIN'),
    'projectId': os.getenv('FIREBASE_PROJECT_ID'),
    'storageBucket': os.getenv('FIREBASE_STORAGE_BUCKET'),
    'messagingSenderId': os.getenv('FIREBASE_MESSAGING_SENDER_ID'),
    'appId': os.getenv('FIREBASE_APP_ID'),
}
FIREBASE_SERVICE_ACCOUNT_KEY_PATH = os.getenv('FIREBASE_SERVICE_ACCOUNT_KEY_PATH', '/path/to/serviceAccountKey.json')
FORCE_DEV_OTP = os.getenv('FORCE_DEV_OTP', '0') in ['1', 'true', 'True']
DEFAULT_COUNTRY_DIAL_CODE = os.getenv('DEFAULT_COUNTRY_DIAL_CODE', '20')  # used to normalize local numbers
```

---

## 11) Optional: CAPTCHA (reCAPTCHA v2 or Turnstile)
Server-side helpers are in `mfa/utils.py`:
- `recaptcha_enabled()`, `verify_recaptcha()`
- `turnstile_enabled()`, `verify_turnstile()`

Example reCAPTCHA v2 setup (Windows Credential Manager via `keyring`, with env fallback):

```python
try:
    import keyring
    RECAPTCHA_SITE_KEY = (keyring.get_password('DjangoRecaptcha', 'SITE_KEY') or '').strip() or None
    RECAPTCHA_SECRET_KEY = (keyring.get_password('DjangoRecaptcha', 'SECRET_KEY') or '').strip() or None
except Exception:
    RECAPTCHA_SITE_KEY = (os.getenv('RECAPTCHA_SITE_KEY') or '').strip() or None
    RECAPTCHA_SECRET_KEY = (os.getenv('RECAPTCHA_SECRET_KEY') or '').strip() or None
```

Place your site key in templates and verify tokens server-side using the helpers.

---

## 12) Database and migrations
The app includes models:
- `MFADevice`: per-user TOTP secret
- `BackupCode`: salted SHA-256 of normalized codes + usage
- `MFALog`: audit trail
- `MFASettings`: feature toggles (singleton)
- `Profile`: per-user phone number

Run migrations:
```bash
python manage.py makemigrations
python manage.py migrate
```

On first access, `MFASettings.load()` guarantees a single row (pk=1) and enforces email factor enabled.

---

## 13) Using the flows
- Login -> user lands on MFA method picker (`mfa:choose_method`) if `MFASettings.always_show_method_picker`.
- Email OTP: sends code and verifies.
- TOTP: `mfa:setup_totp_view` to link; verification page for login.
- Passkeys: start at `mfa:passkey_auth_begin`, complete at `mfa:passkey_auth_complete`.
- Backup Codes: `mfa:backup_codes_view` shows 12 codes on initial open, cached in session to avoid regeneration on refresh; regenerate via POST.
- Profile/Security Hub templates are provided under `mfa/templates/`.

Admin: the site admin can view logs and settings via Django admin. You can add custom admin guard middleware to require admin MFA.

---

## 14) Important passkey notes
- Keep host consistent across the whole flow (avoid flipping between `127.0.0.1` and `localhost`).
- Use the provided `LocalhostRedirectMiddleware` to normalize hosts while skipping all `/mfa/` paths to preserve session cookies during WebAuthn.
- Ensure the passkeys backend is present in `AUTHENTICATION_BACKENDS` so `login(request, user, backend='passkeys.backend.PasskeyModelBackend')` creates a recognized session.

---

## 15) URLs and names used by the app
Key named URLs in `mfa/urls.py`:
- `mfa:login`, `mfa:logout`, `mfa:signup`
- `mfa:choose_method`, `mfa:verify_totp`, `mfa:verify_email`, `mfa:passkey_auth_begin`, `mfa:passkey_auth_complete`
- `mfa:backup_codes`, `mfa:security_hub`, `mfa:profile`

Project-level overrides (recommended) in `mysite/urls.py`:
- `passkeys/auth/begin` -> `mfa.views.passkey_auth_begin`
- `passkeys/auth/complete` -> `mfa.views.passkey_auth_complete`

---

## 16) Messages and UI
We map Django message levels to Bootstrap classes (see `MESSAGE_TAGS` in settings). The app’s templates already display `messages` blocks.

---

## 17) Running locally
```bash
python manage.py runserver 8000
```
Visit `http://localhost:8000` and keep that same host during login and MFA.

---

## 18) Troubleshooting
- Passkey redirects to login after success:
  - Verify you didn’t switch hostnames mid-flow.
  - Check that the session cookie is set on POST `/mfa/passkey/auth-complete/` and that `Set-Cookie` appears in the response.
  - Confirm `passkeys.backend.PasskeyModelBackend` is in `AUTHENTICATION_BACKENDS`.
- TOTP code not accepted:
  - Verify device time, secret, and window.
- Backup codes show zero:
  - Click Regenerate to create a new set; initial open should show 12 and persist across refresh in the current session.
- reCAPTCHA invalid site key:
  - Trim whitespace on keys; confirm source (keyring vs env) and domain match.

---

## 19) Security notes
- Do not expose SMTP creds or secrets in VCS.
- Use HTTPS in production and set `SESSION_COOKIE_SECURE = True`, `CSRF_COOKIE_SECURE = True`.
- Restrict `ALLOWED_HOSTS`.
- Consider rotating backup codes and logging admin actions.

---

## 20) Where things live
- App code: `mfa/`
- Views: `mfa/views.py`
- Models: `mfa/models.py`
- Utils (TOTP, backup codes, CAPTCHA): `mfa/utils.py`
- Allauth defaults: `mfa/auth_settings.py`
- Templates: `mfa/templates/`
- Project settings: `mysite/settings.py`
- Localhost middleware: `mysite/middleware.py`
- Project URLs: `mysite/urls.py`

If you mirror these settings and URLs in your project, the MFA app should work end-to-end with Email, TOTP, Passkeys, and Backup Codes out of the box.

---

## 21) Google Login / Signup (django-allauth)

Allauth is pre-wired via `mfa/auth_settings.py`. To enable Google social login:

1) Create Google OAuth Client (Web Application)
   - Go to Google Cloud Console → APIs & Services → Credentials → Create Credentials → OAuth client ID.
   - Application type: Web application.
   - Authorized JavaScript origins (dev): `http://localhost:8000`
   - Authorized redirect URIs (dev): `http://localhost:8000/accounts/google/login/callback/`
   - Save `Client ID` and `Client Secret`.

2) Add Social App in Django Admin
   - Visit `/admin/` → Social accounts → Social applications → Add.
   - Provider: Google.
   - Name: Google.
   - Client id: paste from step 1.
   - Secret key: paste from step 1.
   - Sites: select your `Site` (ensure `SITE_ID` matches it; see `mysite/settings.py`).
   - Save.

3) Configure allauth behavior (already in `mfa/auth_settings.py`)
   - `SOCIALACCOUNT_AUTO_SIGNUP = True` to skip the third-party signup form when sufficient data is returned.
   - `ACCOUNT_USERNAME_REQUIRED = False` to avoid blocking on username.
   - Redirect URLs:
     - `LOGIN_REDIRECT_URL = '/mfa/profile/'`
     - `ACCOUNT_SIGNUP_REDIRECT_URL = '/mfa/profile/'`
     - `ACCOUNT_LOGOUT_REDIRECT_URL = '/mfa/login/'`

4) Production notes
   - Add your production domain to Google credentials (origins + redirect URI).
   - Update Django `SITE_DOMAIN`, `ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS` accordingly.

---

## 22) CAPTCHA Setup (Google reCAPTCHA v2 or Cloudflare Turnstile)

The app offers server-side helpers in `mfa/utils.py` for both.

1) Keys
   - reCAPTCHA v2 Checkbox: create keys for your domain in Google reCAPTCHA admin.
   - Optional: store keys in Windows Credential Manager via `keyring` (as in `mysite/settings.py`), else use env vars:
     - `RECAPTCHA_SITE_KEY`, `RECAPTCHA_SECRET_KEY`.
   - Turnstile: `TURNSTILE_SITE_KEY`, `TURNSTILE_SECRET_KEY` env vars can be used similarly.

2) Settings example (reCAPTCHA)
```python
try:
    import keyring
    RECAPTCHA_SITE_KEY = (keyring.get_password('DjangoRecaptcha', 'SITE_KEY') or '').strip() or None
    RECAPTCHA_SECRET_KEY = (keyring.get_password('DjangoRecaptcha', 'SECRET_KEY') or '').strip() or None
except Exception:
    RECAPTCHA_SITE_KEY = (os.getenv('RECAPTCHA_SITE_KEY') or '').strip() or None
    RECAPTCHA_SECRET_KEY = (os.getenv('RECAPTCHA_SECRET_KEY') or '').strip() or None
```

3) Template snippet (reCAPTCHA v2 Checkbox)
```html
<script src="https://www.google.com/recaptcha/api.js" async defer></script>
<div class="g-recaptcha" data-sitekey="{{ RECAPTCHA_SITE_KEY }}"></div>

---

## Changelog

### 2025-08-22 — Admin Logs UI Polish

- __Unified filter input icons to match signup style__
  - `mfa/templates/admin/logs_list.html`: All filter inputs now use Bootstrap 4.6 `input-group input-group-sm` with Font Awesome icons in `input-group-prepend` (`.input-group-text`).
  - Date inputs (`From`, `To`) use the same pattern and hide native browser picker icons to avoid double icons.

- __Organized Filters Toolbar__
  - Introduced a `filters-toolbar` wrapper with a small title and structured rows:
    - Row 1 (compact, `g-3`): Search, Outcome, User, IP, Date Range.
    - Row 2: From, To.
    - Controls row: Sort, Order, Page size, and actions.
  - Actions block buttons spaced for Bootstrap 4.6 with `mr-2`/`mb-2`; container has `mt-2` for subtle separation.

- __Grid and spacing improvements__
  - Standardized column widths across breakpoints for a balanced layout.
  - Increased gutters to `g-3` for readability.
  - Methods and Events selection panels use flex to enforce equal height (`align-items-stretch`, `.d-flex`, `.w-100`).

- __Behavior preserved__
  - Existing AJAX filtering and pagination remain unchanged; only markup/CSS were adjusted for a richer, more organized look.

Files touched:
- `mfa/templates/admin/logs_list.html`

#### Implementation details

- **Bootstrap utilities used**: `g-3`, `d-flex`, `flex-wrap`, `align-items-end`, `align-items-stretch`, `mr-2`, `mb-2`, `mt-2`, `w-100`.
- **Grid**:
  - `Search`: `col-12 col-sm-6 col-lg-4`.
  - `Outcome`, `User`, `IP`, `Date Range`: each `col-6 col-sm-6 col-lg-2`.
  - `From`, `To`: each `col-6 col-sm-6 col-lg-2` on a new row.
  - Methods panel: `col-12 col-lg-5`; Events panel: `col-12 col-lg-7`; both `align-items-stretch` and inner `.d-flex.flex-column.w-100` for equal height.
- **Input groups**: All filters use `input-group input-group-sm` with left icons via `input-group-prepend > span.input-group-text > i.fa`.
- **Date inputs**: Hide native picker icons so only the left calendar icon shows. Height/padding aligned with other controls.
- **Actions**: Clear, Reset, Export CSV, Apply grouped under `.toolbar-actions` (flex, wraps). Spacing via `mr-2` and `mb-2`; block has `mt-2`.

#### Customization tips

- **Change icon set or size**: Update the `<i class="fa ...">` classes in `mfa/templates/admin/logs_list.html`. Keep `input-group-sm` for compact height.
- **Adjust spacing**: Replace `g-3` with `g-2`/`g-1` for tighter gutters; tweak button spacing by editing `mr-2`/`mb-2` or adding a CSS rule like `.toolbar-actions .btn + .btn{ margin-left:.5rem; }`.
- **Re-balance columns**: For equal panels, change Methods/Events columns to `col-lg-6`/`col-lg-6`.
- **Single-row filters on large screens**: Widen Search to `col-lg-5` and shrink others to fit one line if desired.
- **ARIA and labels**: All inputs have visible `<label>` elements. If you switch to placeholders-only, add `aria-label` attributes to preserve accessibility.

#### Markup sample (filters row)

```html
<div class="col-12 col-sm-6 col-lg-4">
  <label class="form-label small mb-1">Search</label>
  <div class="input-group input-group-sm">
    <div class="input-group-prepend">
      <span class="input-group-text"><i class="fa fa-search" aria-hidden="true"></i></span>
    </div>
    <input type="text" class="form-control" name="q" placeholder="user, event, method, IP, details...">
  </div>
</div>
```

### 2025-08-21 — Security Hardening

- __CSRF enforcement on sensitive POST endpoints__
  - `mfa/views.py`: Replaced `@csrf_exempt` with `@csrf_protect` on `admin_logout_beacon_view()` and `passkey_auth_complete()`.
  - `admin_logout_beacon_view()` now returns HTTP 204 (no body) to reduce XS-Leak surface.

- __Session validation for passkeys__
  - `mfa/views.py`: `passkey_auth_complete()` now requires a pending MFA session (`SESSION_USER_ID`) before completing WebAuthn.

- __Rate limiting key correctness__
  - `mfa/views.py`: `_rl_key()` now uses `_client_ip(request)` instead of `REMOTE_ADDR`, improving reliability behind proxies.

- __Bug fix (form initialization)__
  - `mfa/views.py`: `backup_code_login_view()` initializes `form = BackupCodeLoginForm(request.POST)` before early-return branches to avoid referencing it before assignment.

- __Admin delete hardening__
  - `mfa/views.py`: `admin_delete_user()` prevents staff-on-staff deletion unless the actor is superuser, in addition to existing protections (no self-delete, no superuser deletion).

- **Singleton safety**
  - `mfa/models.py`: `MFASettings.load()` wrapped in `transaction.atomic()` and uses `select_for_update()`; still enforces a single row (pk=1) and keeps Email factor enabled.

Required follow-ups (for production readiness):

- __Frontend CSRF headers__
  - Since beacon and passkey completion are CSRF-protected, ensure your client sends the CSRF token.
  - Example replacement for `navigator.sendBeacon`:

    ```js
    function getCookie(name) {
      const m = document.cookie.match('(^|;)\\s*' + name + '\\s*=\\s*([^;]+)');
      return m ? m.pop() : '';
    }
    window.addEventListener('pagehide', () => {
      fetch('/mfa/admin/logout-beacon/', {
        method: 'POST',
        keepalive: true,
        headers: { 'X-CSRFToken': getCookie('csrftoken') }
      });
    });
    ```

  - Ensure the POST to `/mfa/passkey/auth-complete/` includes `X-CSRFToken` as well.

- __Production settings (apply in `mysite/settings.py`)__
  - `DEBUG = False`
  - `MFA_FAIL_OPEN = False` (avoid fail-open admin MFA)
  - `SESSION_COOKIE_SECURE = True`
  - `CSRF_COOKIE_SECURE = True`
  - `CSRF_TRUSTED_ORIGINS = ['https://your-domain']`
  - Enable HSTS on HTTPS deployments:
    - `SECURE_HSTS_SECONDS = 31536000`
    - `SECURE_HSTS_INCLUDE_SUBDOMAINS = True`
    - `SECURE_HSTS_PRELOAD = True`
  - If behind a proxy/CDN: `SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')`

### 2025-08-17

- Modernized admin logs filter dropdowns with Choices.js
  - Initialized on every `select` inside `#logsFilterForm` in `mfa/templates/admin/admin_dashboard.html`.
  - Unified, reduced heights via CSS in `mfa/static/mfa/css/style.css` (desktop 32px, mobile 40px); consistent brand-colored focus ring.

- Enforced security key length (Profile.safety_key)
  - `mfa/models.py`: `Profile.safety_key` now `max_length=8`.
  - `mfa/utils.py`: `generate_safety_key()` clamps generated length to 6–8 characters.
  - Run migrations to apply DB schema changes.

- Hardened Email OTP validation
  - `mfa/forms.py`: `EmailOTPForm.clean_code()` rejects codes that are 6 identical digits (e.g., 000000, 111111).
  - Applies to both user and admin OTP verification flows (both use `EmailOTPForm` in `mfa/views.py`).

- Back-to-Top button (global on MFA pages)
  - Markup added in `mfa/templates/mfa/base.html` after the main `{% block content %}`.
  - Styles in `mfa/static/mfa/css/style.css` using brand variables; positioned bottom-right; circular; subtle shadow.
  - Script in `base.html` shows the button after ~200px scroll and smooth-scrolls to top on click. Respects reduced-motion.
  - Updated per UX feedback to remove translucent outer halo on hover/focus.

- Footer and Text Color Theming
  - Introduced `--footer-color`, `--footer-bg`, and `--footer-text` (footer text defaults to `var(--text-on-surface)`).
  - Added semantic `--text-on-surface` for text rendered over colored surfaces and `--text-on-surface-hover` for hover/focus.
  - Removed global override of Bootstrap’s `.text-white` so critical UI (e.g., badges) can stay truly white when needed.

- Inline Validation Icon Pattern
  - Added CSS for `.has-invalid` wrapper and `.invalid-icon` placement; tuned `.form-control.is-invalid` padding and glow.
  - Applied the pattern to `mfa/templates/auth/backup_code_login.html` (Username/Email, Backup Code).




---

## Back-to-Top Button (MFA pages)

The MFA base template includes a floating Back-to-Top button that appears after scrolling and scrolls the page to the top.

- __Markup__: `mfa/templates/mfa/base.html` — `<button id="backToTopBtn" class="back-to-top" aria-label="Back to top">`
- __Styles__: `mfa/static/mfa/css/style.css` — see the `.back-to-top` rules
- __Script__: inline in `base.html` — shows the button after ~200px scroll and scrolls to top on click

### Compatibility
- Uses native `window.scrollTo({ behavior: 'smooth' })` when available.
- Falls back to a requestAnimationFrame animation (`smoothScrollToTop`) for browsers without native smooth scrolling.

### Customize
- __Position__: change `bottom`/`right` in `.back-to-top` (20px desktop, 16px mobile)
- __Size__: adjust `width`/`height` (46px desktop, 42px mobile)
- __Colors__: controlled by CSS variables in `:root` (`--brand-color`, `--brand-color-hover`)
- __Shadow__: edit `box-shadow` on base and `:hover/:focus` rules (halo removed by default)
- __Threshold__: change `showAt` (default `200`) in the Back-to-Top script
- __Icon__: uses Font Awesome chevron — update the `<i class="fas fa-chevron-up">` as needed

## Admin Logs Filters

The Security Center’s “Recent Logs” table supports the following filters (see `mfa/templates/admin/admin_dashboard.html` → `#logsFilterForm`):

- __Outcome__: All, Failures, Successes
- __Method__: MFA method code (e.g., Email, TOTP, Passkey, Backup)
- __Event__: Audit event type (login, verify, setup, regenerate, etc.)
- __Username__: Exact or partial username
- __IP__: Exact or partial IP address
- __From / To__: Date range (YYYY-MM-DD)

Behavior:

- __Apply__ builds a clean query string with only non-empty fields and resets logs page to 1.
- __Reset__ clears filters while preserving the users list page if present.
- Pressing __Enter__ in any field applies filters (native form submit is prevented).
- Filters for Outcome, Method, Event are enhanced with __Choices.js__ (searchable, no resort), with compact heights aligned to inputs.

These map to query params: `outcome`, `method`, `event`, `user`, `ip`, `from`, `to`, plus `page` (logs) and optional `users_page` (recent users pagination).

---

## 35) Remember Me Option

The app supports a lightweight "Remember me" behavior controlled via the session key `remember_me` and applied by `mfa/views.py` → `_apply_remember_me(request)`.

- __How it works__
  - If `request.session['remember_me']` is truthy when `_apply_remember_me()` runs, the session is made persistent for `SESSION_COOKIE_AGE` seconds.
  - If the key exists but is falsy, the session will expire on browser close.
  - If the key is absent, no changes are made.

- __Where it’s used__
  - `_apply_remember_me()` is called after successful MFA completion and in a few flows after login.

- __Setup in your login form__ (example)
  - Add a checkbox named `remember_me` to your login form and, on successful primary auth (before redirecting into MFA), set the flag in the session:

```python
def login_view(request):
    if request.method == 'POST':
        # ... validate username/password ...
        remember = bool(request.POST.get('remember_me'))
        request.session['remember_me'] = remember
        # redirect into MFA flow (e.g., choose_method)
        return redirect('mfa:choose_method')
    # GET -> render login form with a remember_me checkbox
```

- __Django settings__
  - Configure `SESSION_COOKIE_AGE` (e.g., two weeks = `1209600`).
  - Consider `SESSION_COOKIE_SECURE` and other production flags.

---

## 36) Security Summary Email and CSV Attachment

The Security Center can send a periodic summary email with a 7‑day chart and an optional CSV attachment of recent MFA logs.

- __Admin UI__
  - Page: `mfa/templates/admin/report_settings.html` (route: `mfa:admin_report_settings`).
  - Settings (stored in `MFASettings` singleton):
    - `report_enabled`: enable/disable scheduled sends.
    - `report_frequency_days`: cadence for scheduled emails.
    - `report_recipients`: comma/space list of recipients.
    - `report_csv_days`: how many days to include in the attached CSV (default 7).
  - You can also trigger an immediate send via the "Send Now" action on this page.

- __Management command__
  - Command: `python manage.py send_security_summary`
  - Options:
    - `--force`: send regardless of `next_send_at`.
    - `--dry-run`: compute and log, but do not send.
    - `--to alice@example.com bob@example.com`: one‑off override recipients.
    - `--dump-html path.html`: write the rendered HTML and exit.

- __CSV attachment__
  - Columns: `created_at`, `user_id`, `event`, `method`, `ip_address`, `user_agent`, `details`.
  - The generator quotes all fields, replaces newlines/tabs with spaces, collapses excessive whitespace, and prepends a UTF‑8 BOM for Excel/Sheets compatibility.
  - Immediate send and scheduled send share the same hardened behavior.

---

## 37) Graphs Options (Admin Dashboard)

The Admin Dashboard (`mfa/templates/admin/admin_dashboard.html`) includes a 7‑day stacked outcomes chart with two modes:

- __Counts__: raw successes/failures per day.
- __Percent__: normalized to 0–100% per day.

Notes:
- The previous "Show values" toggle has been removed for clarity. Value labels are rendered automatically only when segments are large enough to remain legible.
- A "Download PNG" button lets you export the chart image.

---

## 34) Rate Limiting and Lockouts

This app ships with layered protections to slow brute‑force attempts against both the primary password login and MFA verification steps. Limits are stored in the Django cache to avoid schema changes. Use a robust cache (e.g., Redis) in production.

### Login (username/password)

Protections applied in `mfa/views.py` → `login_view()` and `admin_login_view()`:

- __Per IP + Username counter__
  - Blocks repeated wrong passwords for a specific account from a given IP.
  - Settings:
    - `LOGIN_FAIL_LIMIT` (default 5)
    - `LOGIN_FAIL_WINDOW_SECONDS` (default 600)
    - Admin overrides: `ADMIN_LOGIN_FAIL_LIMIT`, `ADMIN_LOGIN_FAIL_WINDOW_SECONDS` (fallback to user values if not set)

- __IP‑wide counter__
  - Blocks all usernames from the same IP after too many recent failures, preventing trying many emails from one IP.
  - Settings:
    - `LOGIN_IP_FAIL_LIMIT` (default 20)
    - `LOGIN_IP_FAIL_WINDOW_SECONDS` (default 600)
    - Admin overrides: `ADMIN_LOGIN_IP_FAIL_LIMIT` (default 10, or falls back to `LOGIN_IP_FAIL_LIMIT`), `ADMIN_LOGIN_IP_FAIL_WINDOW_SECONDS` (fallback to `LOGIN_IP_FAIL_WINDOW_SECONDS`)

- __User feedback__
  - Error messages include the remaining attempts before temporary lockout, e.g.,
    - `Invalid username or password. Please try again. (2 attempts left before temporary lockout)`
  - Admin “not staff” attempts are also counted and include remaining attempts.

### MFA verification (Email OTP, TOTP)

Applied in the relevant verification views in `mfa/views.py`:

- __Per‑user lockout for repeated MFA failures__ using cache keys.
- Settings:
  - `MFA_LOCKOUT_MAX_FAILURES` (default 5)
  - `MFA_LOCKOUT_WINDOW_SECONDS` (default 600)

When the threshold is reached, the user is temporarily locked out from verifying that factor and receives a clear message to try again later.

### Admin MFA

- Admin MFA is Email OTP only. Admin TOTP verification route was intentionally removed.

### Cache keys (for reference)

Key format examples (implementation detail, may change):
- Login per user+IP: `mfa:rl:login_fail:<ip>:<username>`
- Login IP‑wide: `mfa:rl:login_fail_ip:<ip>`
- Admin login per user+IP: `mfa:rl:admin_login_fail:<ip>:<username>`
- Admin login IP‑wide: `mfa:rl:admin_login_fail_ip:<ip>`
- MFA factor failures: `mfa:lock:<type>:<user_id>` (type varies per factor)

### Operations notes

- __Clearing lockouts__: entries expire automatically after their windows. To force clear, flush the specific keys in your cache backend (e.g., Redis) or wait for TTL.
- __Cache backend__: In production use Redis/memcached. The local default in Django may not be shared between processes.
- __UX__: Messages are designed to be user‑friendly and consistent. You can customize wording in `mfa/views.py`.

### Security rationale

- Combining per‑user and per‑IP limits thwarts targeted and spray attacks.
- The IP‑wide limiter closes the gap where an attacker rotates emails from one IP.

Make sure your context provides `RECAPTCHA_SITE_KEY` (e.g., via a context processor or passing from the view).

4) Server-side verify (reCAPTCHA)
```python
from mfa.utils import recaptcha_enabled, verify_recaptcha
{{ ... }}

def my_view(request):
    if recaptcha_enabled():
        ok, errors = verify_recaptcha(request)
        if not ok:
            messages.error(request, 'Captcha failed: ' + ','.join(errors))
            return redirect('somewhere')
```

5) Turnstile (Cloudflare)
Use `turnstile_enabled()` and `verify_turnstile(request)` similarly. The client-side widget differs; include the Turnstile script and site key per Cloudflare docs.

---

## 23) Production Configuration Checklist

- Use HTTPS everywhere. Set:
  - `SECURE_SSL_REDIRECT = True`
  - `SESSION_COOKIE_SECURE = True`
  - `CSRF_COOKIE_SECURE = True`
  - Consider HSTS: `SECURE_HSTS_SECONDS`, `SECURE_HSTS_INCLUDE_SUBDOMAINS`, `SECURE_HSTS_PRELOAD`
- `ALLOWED_HOSTS = ['your.domain']`
- `CSRF_TRUSTED_ORIGINS = ['https://your.domain']`
- WebAuthn RP ID must be your registrable domain:
  - `FIDO_SERVER_ID = 'your.domain'`
- Disable localhost normalization middleware in production (keep it guarded by `if DEBUG:` as in this project).
- Update Google OAuth credentials to include your production origin and callback.
- Provide real SMTP credentials and possibly a dedicated email service.
- Rotate secrets and keep them out of VCS (use env vars or secret managers).

---

## 24) Integrating into an Existing Site

1) URLs and Navigation
   - Include `path('mfa/', include(('mfa.urls', 'mfa'), namespace='mfa'))`.
   - Add links to MFA pages (e.g., Security Hub, Profile) in your site navbar.

2) Login Flow
   - Keep your existing username/password login.
   - After primary auth, redirect to `mfa:choose_method` (or enable `MFASettings.always_show_method_picker`).
   - Ensure the session persists through MFA; keep host consistent for passkeys.

3) Templates
   - Either use the provided templates under `mfa/templates/` or copy and restyle them.
   - Preserve form names/fields used by views (e.g., `method`, `next`, passkeys form with `passkeys` JSON).

4) Admin
   - Standard Django admin works. You can extend with middleware to require admin MFA when accessing `/admin/`.

5) Backup Codes
   - Initial open shows 12 codes; refresh does not regenerate.
   - Codes are normalized (uppercase, hyphens/spaces ignored) and stored as salted SHA-256.

6) SMS (optional)
   - For production SMS, implement a real provider in place of the dev helper or use Firebase as shown.

7) Testing
   - Test on `http://localhost:8000` end-to-end for Email, TOTP, Passkeys, and Backup Codes before switching domains.

---

## 25) Environment Variables and .env Example

Recommended variables (adjust to your infra):

```env
# Django
DEBUG=1
SECRET_KEY=change-me
ALLOWED_HOSTS=localhost,127.0.0.1
CSRF_TRUSTED_ORIGINS=http://localhost:8000

# Email (SMTP)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=1
EMAIL_HOST_USER=your_email@example.com
EMAIL_HOST_PASSWORD=app_password_or_secret

# Brand colors (optional overrides; keep in sync with style.css :root)
BRAND_COLOR=#2b77ba
BRAND_COLOR_HOVER=#1b3390
BRAND_COLOR_WEAK=#076d6d5b

# WebAuthn
FIDO_SERVER_ID=localhost
FIDO_SERVER_NAME=GreenShield MFA

# Firebase (optional SMS)
FIREBASE_API_KEY=
FIREBASE_AUTH_DOMAIN=
FIREBASE_PROJECT_ID=
FIREBASE_STORAGE_BUCKET=
FIREBASE_MESSAGING_SENDER_ID=
FIREBASE_APP_ID=
FIREBASE_SERVICE_ACCOUNT_KEY_PATH=
FORCE_DEV_OTP=0
DEFAULT_COUNTRY_DIAL_CODE=20

# CAPTCHA (choose one provider)
RECAPTCHA_SITE_KEY=
RECAPTCHA_SECRET_KEY=
TURNSTILE_SITE_KEY=
TURNSTILE_SECRET_KEY=
```

Tip: load with `python-dotenv` or your platform’s secret store. Never commit real secrets.

---

## 26) Static Files and collectstatic

- In development, `STATICFILES_DIRS = [BASE_DIR / 'static']` serves assets.
- For production:
  - Set `STATIC_URL = '/static/'` and `STATIC_ROOT = BASE_DIR / 'staticfiles'` (or your path).
  - Run `python manage.py collectstatic` during build/deploy.
  - Ensure your web server or storage (e.g., S3 + CDN) is configured to serve from `STATIC_ROOT`.

---

## 27) Django Sites Framework

- Ensure `django.contrib.sites` is in `INSTALLED_APPS` and `SITE_ID` is set.
- In `/admin/sites/site/` set your domain (e.g., `localhost:8000` for dev, `your.domain` for prod).
- Map the Google `SocialApp` to this Site. Mismatched Site leads to social login errors.

---

## 28) Required Partials and Template Includes

Several templates include shared partials:
- `partials/navbar.html`
- `partials/footer.html`

If your project doesn’t have them, create simple versions under `templates/partials/` or remove the includes and inline your site chrome. Ensure your `TEMPLATES` config has `DIRS: [BASE_DIR / 'templates']`.

---

## 29) Context Processor Example (Expose CAPTCHA Keys)

To avoid passing the site key in every view, add a simple context processor, e.g. `mysite/context_processors.py`:

```python
def captcha_site_keys(request):
    from django.conf import settings
    return {
        'RECAPTCHA_SITE_KEY': getattr(settings, 'RECAPTCHA_SITE_KEY', None),
        'TURNSTILE_SITE_KEY': getattr(settings, 'TURNSTILE_SITE_KEY', None),
    }
```

And register it in `TEMPLATES[...]['OPTIONS']['context_processors']`:

```python
'mysite.context_processors.captcha_site_keys',
```

Now templates can reference `{{ RECAPTCHA_SITE_KEY }}` or `{{ TURNSTILE_SITE_KEY }}` safely.

---

## 30) Final Validation Checklist

- __Apps__: `mfa`, `passkeys`, `django.contrib.sites`, `allauth`, `allauth.account`, `allauth.socialaccount`, and `allauth.socialaccount.providers.google` (if using Google).
- __Auth backends__: include `allauth` and `passkeys.backend.PasskeyModelBackend`.
- __Middleware__: includes `AccountMiddleware`; localhost normalization only in `DEBUG` and excludes `/mfa/` paths.
- __Templates__: project `templates/` directory added; partials exist or includes removed.
- __URLs__: `accounts/`, `mfa/` included; passkeys begin/complete overridden to `mfa.views`.
- __WebAuthn__: `FIDO_SERVER_ID` matches current host (dev) or registrable domain (prod). Host remains consistent across flow.
- __Email__: SMTP configured; password reset, email OTP tested.
- __TOTP__: setup QR renders; verification accepts correct code.
- __Passkeys__: register, then authenticate successfully; session persists post-complete.
- __Backup Codes__: first open shows 12 codes; refresh doesn’t regenerate; codes verify once then mark used.
- __SMS (optional)__: dev OTP or provider tested.
- __CAPTCHA__: widget renders; server verification fails/pass as expected.
- __Sites__: domain configured; Google `SocialApp` linked to the right Site.
- __Static__: production runs `collectstatic` and serves assets correctly.

---

## 31) One‑Click Brand Color Theming

The site’s green accents are centralized as CSS custom properties so you can rebrand quickly without hunting through styles.

File: `mfa/static/mfa/css/style.css`

```css
/* One-click MFA color theming */
:root {
  --brand-color: #55833d;        /* primary brand color */
  --brand-color-hover: #466d33;  /* hover/darker variant */
  --brand-color-weak: #55833d5b; /* translucent accent (focus rings, hovers) */
}

/* Example usages */
.auth-helper .brand-link { color: var(--brand-color) !important; }
.auth-helper .brand-link:hover,
.auth-helper .brand-link:focus { color: var(--brand-color-hover) !important; }
```

How to change the brand color in one step:

1. Open `mfa/static/mfa/css/style.css`.
2. Update the three variables under the `:root` block.
3. Ensure this stylesheet loads after Bootstrap so the variables take effect.

Notes:

- Email templates often need inline colors for maximum client compatibility and to satisfy IDE CSS validators. Web pages (non-email) read from CSS variables.
- If you want dynamic colors from settings in webpages, you can add a context processor and map to `style="color: var(--brand-color)"` or classes using the variables. This repo already ships a `brand_colors` context processor for convenience in templates.

---

## 31a) Semantic Text Color on Surfaces

We centralize the text color used on colored surfaces (buttons, badges, footer, icon chips) via CSS variables in `mfa/static/mfa/css/style.css` `:root`:

```css
:root {
  --text-on-surface: #853737;             /* default text over colored surfaces */
  --text-on-surface-hover: var(--text-on-surface); /* hover/focus variant */
}
```

Usage examples:

- Buttons like `btn-brand`, `btn-green` use `color: var(--text-on-surface)` and on hover/focus `color: var(--text-on-surface-hover)`.
- The Back‑to‑Top button and small info icon chips (`.icon5child`) also read these variables on hover.
- Footer text is controlled by `--footer-text`, which defaults to `var(--text-on-surface)`. See footer variables in the same file:
  - `--footer-color` (independent background)
  - `--footer-bg`, `--footer-text`

Notes and guidance:

- We do NOT override Bootstrap’s `.text-white` anymore. If you need guaranteed white text (e.g., status badges like “Not set up”), use the `text-white` class or an explicit color.
- To customize hover contrast globally, override only the hover variable in a scope:

```css
/* Global override */
:root { --text-on-surface-hover: #ffffff; }

/* Scoped override (e.g., footer) */
footer { --text-on-surface-hover: #f8f9fa; }
```

This semantic naming avoids hard‑coding white and keeps themes flexible while preserving accessibility.

---

## 31b) Footer Theming

Footer colors are controlled independently from the brand color in `mfa/static/mfa/css/style.css` `:root`:

```css
:root {
  --footer-color: #24a8a1;        /* footer background */
  --footer-bg: var(--footer-color);
  --footer-text: var(--text-on-surface); /* footer text color */
}
```

How it’s applied (see `mfa/templates/partials/footer.html` which uses an inner `.bg-dark` div):

```css
footer { background-color: var(--footer-color); color: var(--footer-text); }
footer .bg-dark { background-color: var(--footer-color) !important; color: var(--footer-text) !important; }
footer a { color: inherit; }
footer a:hover, footer a:focus { color: var(--text-on-surface-hover); }
```

You can adjust `--footer-text` separately from `--text-on-surface` if needed, or scope a different hover color by overriding `--text-on-surface-hover` inside `footer { ... }`.

---

## 31c) Inline Validation Icon Pattern

To show a red validation icon inside inputs when a field has errors, the stylesheet provides these helpers (see `mfa/static/mfa/css/style.css`):

- `.form-control.is-invalid` — adds red border, subtle glow, and right padding
- `.has-invalid` — set on the field wrapper to position the icon
- `.invalid-icon` — absolutely positioned Font Awesome icon inside the input on the right

Template usage example (Django forms):

```django
<div class="mb-3 has-invalid">
  <label for="{{ form.field.id_for_label }}" class="form-label">Field</label>
  {% if form.field.errors %}
    {{ form.field.as_widget(attrs={'class': 'form-control is-invalid'}) }}
    <i class="fas fa-exclamation-circle invalid-icon" aria-hidden="true"></i>
    <div class="text-danger small mt-1">{{ form.field.errors|striptags }}</div>
  {% else %}
    {{ form.field }}
  {% endif %}
  </div>
```

This pattern has been applied to `mfa/templates/auth/backup_code_login.html` for the Username/Email and Backup Code fields.

---

## 31d) Color Variables Reference

All site theming variables live in `mfa/static/mfa/css/style.css` under the `:root` block. Override globally or scope inside a container (e.g., `footer { ... }`).

```css
:root {
  /* Brand */
  --brand-color: #242fa8;            /* primary brand */
  --brand-color-hover: #107993;      /* darker/hover brand */
  --brand-color-weak: #07416d5b;     /* translucent ring/hover accent */

  /* Text on colored surfaces */
  --text-on-surface: #853737;        /* base text over buttons/badges/footers */
  --text-on-surface-hover: var(--text-on-surface); /* hover/focus text */

  /* Footer */
  --footer-color: #24a8a1;           /* footer background */
  --footer-bg: var(--footer-color);  /* alias */
  --footer-text: var(--text-on-surface); /* footer text color */
}
```

Quick usage map:

- Buttons: `btn-brand`, `btn-green` → text uses `--text-on-surface` and `--text-on-surface-hover` on hover.
- Back-to-Top: base text uses `--text-on-surface`; hover uses `--text-on-surface-hover`.
- Footer: background `--footer-color`; text `--footer-text`; links hover → `--text-on-surface-hover`.
- Bootstrap `.text-white` is not overridden; use it when you need actual white text.

---

## 32) Email Theming and Brand Color Alignment

Emails don’t load your site CSS, so brand colors must be provided via Django settings/context. This project exposes them through `mfa.context_processors.brand_colors`, and templates use a single inline CSS property with a Django default filter fallback.

- Settings (`mysite/settings.py`):
  ```python
  # Align with :root in style.css
  BRAND_COLOR = os.getenv('BRAND_COLOR', '#2b77ba')
  BRAND_COLOR_HOVER = os.getenv('BRAND_COLOR_HOVER', '#1b3390')
  BRAND_COLOR_WEAK = os.getenv('BRAND_COLOR_WEAK', '#076d6d5b')
}
  ```

- Context processor (`mfa/context_processors.py`):
  ```python
  def brand_colors(request):
{{ ... }}
      return {
          'brand_color': getattr(settings, 'BRAND_COLOR', '#2b77ba'),
          'brand_color_hover': getattr(settings, 'BRAND_COLOR_HOVER', '#1b3390'),
          'brand_color_weak': getattr(settings, 'BRAND_COLOR_WEAK', '#076d6d5b'),
      }
  ```

- Email templates (example `mfa/templates/email/base_email.html`):
  ```html
  <div class="email-header" style="background-color: {{ brand_color|default:'#2b77ba' }};">
      ...
  </div>
  ```

- Rendering emails: pass `request` to `render_to_string()` so context processors apply:
  ```python
  html = render_to_string('email/mfa_code_email.html', {'code': code}, request=request)
  ```

### Troubleshooting: Emails show the wrong color

- Ensure you restarted the dev server after changing settings.
- Check environment variable overrides (Windows PowerShell):
  ```powershell
  Get-ChildItem Env:BRAND_COLOR*
  ```
  If present and set to old values, update or remove them, then restart the server.
- Re-send a fresh email (don’t rely on previously rendered messages).
- Optional: temporarily print the active color inside an email template for debugging:
  ```html
  <!-- Debug: active brand color: {{ brand_color }} -->
  ```

---

## 33) Security Key UI and Styling (Developer Notes)

- Purpose: The “Security key” is an anti‑phishing phrase shown to users for visual verification.
- Where used (web): `mfa/templates/auth/profile.html`, `auth/verify_email.html`, `auth/password_reset_form.html`, `auth/password_reset_done.html`, `admin/admin_verify_email.html`.
- Visuals:
  - Shield icon uses brand color: `style="color: var(--brand-color);"`.
  - Info icon is gray with a subtle hover darken (web only), using `.info-icon` class.
  - The key value itself uses dark text for readability: add `text-dark` on the key element.
- Copy button (web only): On `profile.html`, a small outline-secondary button copies the key to clipboard and provides success feedback (icon changes to checkmark, tooltip text updates).
- Email templates: Avoid hover effects. Keep icon brand color inline; keep the key text dark for legibility.
- Brand color: Controlled via CSS variables in `mfa/static/mfa/css/style.css` (`--brand-color`, `--brand-color-hover`, `--brand-color-weak`).

Quick edit checklist:

- Keep shield icon brand‑colored; do not color the key text with brand color—use `text-dark`.
- Ensure `.info-icon` has title tooltip text explaining the key.

### Implementation details

- Security key markup (web pages):
  - Icon + label + value grouped together; the shield icon is inline‑styled with `color: var(--brand-color)`.
  - Key value uses a dark text style for legibility.
    - `auth/profile.html`: key shown inside a small light badge element with border and id `safety-key-text`.
    - Other pages: key shown as a bold inline element next to the label.
  - Info icon uses class `.info-icon` and has a descriptive `title` tooltip.

- Copy to clipboard (profile only):
  - Elements:
    - Source: `#safety-key-text` (contains the key text).
    - Button: `#copy-safety-key` (small outline button next to the key).
  - Behavior:
    - Uses the modern Clipboard API with a safe fallback for older browsers.
    - On success, the icon swaps to a checkmark and the button tooltip/title changes to confirm copy, then reverts after a short delay.
  - Accessibility:
    - Button includes `aria-label="Copy security key"`.
    - Icons use `aria-hidden="true"` where appropriate.

- Web vs Email behavior:
  - Web: shield icon in brand color; info icon with subtle hover darken; key value in dark text; copy button exists only on the profile page.
  - Email: no hover effects; shield stays brand colored via inline style; key text remains dark for legibility.

- Templates updated today (key text set to dark, icons consistent):
  - `mfa/templates/auth/profile.html`
  - `mfa/templates/auth/verify_email.html`
  - `mfa/templates/auth/password_reset_form.html`
  - `mfa/templates/auth/password_reset_done.html`
  - `mfa/templates/admin/admin_verify_email.html`

- Helper text (profile page):
  - Adds a muted paragraph below the key clarifying that this key appears in email footers to help users recognize official messages.

### Canonical markup snippet (web pages)

```html
<!-- Security key block (generic pages) -->
<div class="mx-auto my-2" style="max-width:260px;">
  <div class="border rounded small p-1 px-2 d-flex align-items-center justify-content-between" style="background:#f6f9fc; font-size: 0.85rem; line-height:1;">
    <div class="d-flex align-items-center">
      <i class="fa fa-shield-alt mr-1" aria-hidden="true" style="font-size:0.9rem; color: var(--brand-color);"></i>
      <span class="text-muted">Security key:</span>
      <strong class="ml-1 text-dark">{{ safety_phrase }}</strong>
    </div>
    <i class="fa fa-info-circle info-icon ml-1" aria-hidden="true" title="This key appears in our email footers. Use it to recognize official messages from us." style="font-size: 0.8rem; line-height:1;"></i>
  </div>
  <!-- Optional helper text under block (profile uses a separate paragraph) -->
</div>
```

Profile variant (with copy button):

```html
<div class="d-flex align-items-center">
  <span class="badge bg-light text-dark border" id="safety-key-text" style="font-size: 0.9rem; padding: .35rem .5rem;">{{ safety_phrase }}</span>
  <button class="btn btn-sm btn-outline-secondary ml-2" type="button" id="copy-safety-key" title="Copy security key" aria-label="Copy security key">
    <i class="fas fa-copy" aria-hidden="true"></i>
  </button>
  <i class="fa fa-info-circle info-icon ml-2" aria-hidden="true" title="This key appears in our email footers. Use it to recognize official messages from us." style="font-size: 0.8rem; line-height:1;"></i>
</div>
```

Recommended tooltip text (aligns with helper text):

- Use: “This key appears in our email footers. Use it to recognize official messages from us.”
- Avoid mentioning login pages to keep the message consistent.

### Security Notes icon and modal

- Purpose: Provide quick access to concise security guidance from the top-right of auth cards.
- Placement: A small info icon button at the top-right of the main card opens a Bootstrap 4 modal titled “Security notes”.
- Icon color: Uses the brand color via CSS variable with a dedicated class.
  - CSS: `.info-icon.brand { color: var(--brand-color); } .info-icon.brand:hover { color: var(--brand-color); }`
- Modal action button: Uses brand color via `.btn-brand`.
  - CSS: `.btn-brand { background-color: var(--brand-color); border-color: var(--brand-color); color: #fff; } .btn-brand:hover, .btn-brand:focus { background-color: var(--brand-color); border-color: var(--brand-color); filter: brightness(0.92); color: #fff; }`
- Updated templates:
  - `mfa/templates/auth/profile.html`
  - `mfa/templates/auth/verify_email.html`
  - `mfa/templates/auth/password_reset_form.html`
  - `mfa/templates/auth/password_reset_done.html`
  - `mfa/templates/admin/admin_verify_email.html`

Canonical snippet (icon and modal):

```html
<style>
  .info-icon { color: #6c757d; transition: color .15s ease-in-out; }
  .info-icon:hover { color: #495057; }
  /* Brand-colored variant for top-right notes button */
  .info-icon.brand { color: var(--brand-color); }
  .info-icon.brand:hover { color: var(--brand-color); }
  /* Brand action button */
  .btn-brand { background-color: var(--brand-color); border-color: var(--brand-color); color: #fff; }
  .btn-brand:hover, .btn-brand:focus { background-color: var(--brand-color); border-color: var(--brand-color); filter: brightness(0.92); color: #fff; }
  /* Ensure :root or body defines --brand-color (see css) */
  /* :root { --brand-color: #00A884; } */
  </style>

<!-- In card header/top-right -->
<div class="text-right mb-1">
  <button type="button" class="btn btn-link p-0" data-toggle="modal" data-target="#securityNotesModal" title="Security notes" aria-label="Open security notes">
    <i class="fa fa-info-circle info-icon brand" aria-hidden="true" style="font-size: 1rem;"></i>
  </button>
  </div>

<!-- Modal (place near page footer) -->
<div class="modal fade" id="securityNotesModal" tabindex="-1" role="dialog" aria-labelledby="securityNotesLabel" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered" role="document">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="securityNotesLabel"><span class="brand-color">S</span>ecurity notes</h5>
        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
          <span aria-hidden="true">&times;</span>
        </button>
      </div>
      <div class="modal-body text-left">
        <ul class="mb-0 pl-3" style="list-style: disc;">
          <li class="mb-1">Your <strong>security key</strong> appears in our <strong>email footers</strong>. Make sure it matches yours to spot phishing.</li>
          <li class="mb-1">Never share your one-time codes, backup codes, or security key with anyone.</li>
          <li class="mb-1">Only enter codes on our official site. Check the address bar before proceeding.</li>
          <li class="mb-1">If something looks suspicious, stop and contact support.</li>
        </ul>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-brand" data-dismiss="modal">Got it</button>
      </div>
    </div>
  </div>
</div>

---

## Admin Guide (Features Explained)

This section explains every page in the custom Admin area under `mfa/templates/admin/`. Use this as a quick user guide for operators and as a map for developers.

### Navigation basics

- __Dashboard and Sections__: The admin opens at the Security Dashboard. Use the left navigation to reach Monitoring, Analytics, Policies, Users, and Settings.
- __Filters and Exports__: Most tables and charts include filters (top bar) and CSV/PNG export buttons where applicable.
- __Permissions__: All pages are protected for staff-only use. Some actions require superuser.

### Admin Shell

- __Layout Base__ (`admin_base.html`): Common header, sidebar, brand styles, and JS/CSS includes shared by all admin pages.

### Security Center and Monitoring

- __Security Dashboard__ (`admin_dashboard.html`)
  - KPIs: total authentications, success/failure ratio, recent users.
  - 7‑day outcomes chart: toggle counts vs percent; download PNG.
  - Recent logs: filter by outcome, method, event, user, IP, date; quick links to full logs.

  - Purpose: High‑level health view for admins at a glance.
  - Data sources: aggregated queries in `mfa/views.py` and `mfa/utils.py`. Charts use in‑template JS fed by context.
  - How to:
    1) Use the outcomes toggle (Counts/Percent) to compare days fairly.
    2) Click any segment/legend to isolate a series.
    3) Use the recent logs quick filters to jump into `Logs List` with the same criteria.
  - Export: use the chart’s “Download PNG”.

- __Real‑Time Monitoring__ (`realtime_monitoring.html`)
  - Live Activity Feed: streaming MFA events, incidents, anomalies with filters (All/Success/Failures/Warnings), pause and clear controls.
  - System Stats: active sessions, auth rate, alerts; auto refresh.
  - Export: download feed snapshot as CSV; refresh pulls latest via AJAX.

  - Purpose: Catch spikes and failures as they happen.
  - Data sources: AJAX endpoints in `mfa/ajax_views_realtime.py` → `live_activity_feed`, `live_system_stats` (see `mfa/urls.py`).
  - Notes: Statuses normalized to `success|failure|warning`; dedup keyed by `timestamp+message`.
  - How to:
    1) Use filter buttons to focus on Failures during an incident.
    2) Pause to investigate without losing state; Resume to continue streaming.
    3) Export CSV to attach to incident tickets.

- __ML Risk Engine__ (`ml_risk_engine.html`)
  - KPIs: overall risk score, high/medium/low risk counts.
  - Charts: risk trend, performance, and distribution; wired to JSON endpoints for live data.
  - Actions: refresh data and export visualizations.

  - Purpose: Understand model risk posture and distribution.
  - Data sources: `mfa/views_admin_api.py` → `admin_api_ml_summary`, `admin_api_risk_distribution`.
  - How to:
    1) Review KPI tiles to gauge current risk load.
    2) Use Risk Distribution to spot skew (e.g., rising High risk).
    3) Refresh to pull latest without reloading the page.

- __Threat Intelligence__ (`threat_intelligence.html`)
  - Ingested threat feeds, indicators of compromise (IOCs), and auto‑response status.
  - Manual block/allow actions, feed health, last update times.

- __Incident Response__ (`incident_response.html`)
  - Open incidents by severity, status timeline, categories.
  - Actions: acknowledge, assign, resolve; notes and audit trail links.

  - Purpose: Triage and manage security incidents.
  - Data sources: `SecurityIncident` model; timeline assembled in view.
  - How to:
    1) Sort by severity; open the top item.
    2) Assign an owner, add notes, change status to In‑progress.
    3) Link evidence (logs, device, geolocation) and Resolve when done.

- __Forensics & Audit__ (`forensics_audit.html`)
  - Audit KPIs: logs count, investigations, compliance checks.
  - Timeline of key audit events; modal with detailed artifacts.

  - Purpose: Provide evidence trails for audits and investigations.
  - Data sources: `MFALog`, investigation models; rendered timeline.
  - How to:
    1) Filter by date and category.
    2) Open an event to see artifacts; export as needed.

### Devices and Behavior

- __Device Fingerprinting__ (`device_fingerprinting.html`)
  - Device inventory, risk breakdown doughnut, and top risky fingerprints.
  - Drill‑downs for device attributes and history.

  - Purpose: Track devices and spot risky fingerprints.
  - Data sources: device tables; risk distribution from admin API.
  - How to:
    1) Use the distribution chart to identify risk clusters.
    2) Open a device to view attributes (UA, platform, IP history) and linked users.

- __Device Analytics__ (`device_analytics.html`)
  - Device age distribution chart, platform breakdown, usage trends.
  - Tables for most/least active devices; export available.

- __User Behavior Analytics__ (`user_behavior_analytics.html`)
  - Anomaly detections by type and frequency; user risk drivers.
  - Recent anomalies list with user, action, and timestamp.

- __Geolocation Tracking__ (`geolocation_tracking.html`)
  - Map/list of login locations, distance anomalies, velocity checks.
  - Filters for country, ASN, and risk flags.

### Risk and Policies

- __Risk Assessment__ (`risk_assessment.html`)
  - Risk scoring inputs and weights; distribution across users.
  - High‑risk user list with recommended actions.

- __Predictive Analytics__ (`predictive_analytics.html`)
  - Model performance snapshots, feature importances.
  - Forecasted risk trends; comparison vs actuals.

- __Security Policies__ (`security_policies.html`)
  - Policy toggles and thresholds (e.g., enforce MFA methods, lockout limits).
  - Save/preview changes and view policy audit log.

### Users and Sessions

- __Users List__ (`users_list.html`)
  - Search, filter, paginate. Bulk actions: activate, deactivate, delete, send password reset.
  - Columns: username, methods enrolled, last login/IP, risk status.

  - Purpose: Operate on user accounts at scale.
  - Data sources: `User`/`Profile` queries in `mfa/views.py`.
  - How to:
    1) Use search and filters to narrow a cohort.
    2) Select rows → choose a bulk action (e.g., Send reset).
    3) Click a username to open `User Detail`.

- __User Detail__ (`user_detail.html`)
  - Full profile: enrolled MFA methods (TOTP, Email/SMS OTP, Passkeys, Backup Codes).
  - Session history, recent MFA logs, device fingerprints linked to the user.

  - Purpose: 360° view for support and security operations.
  - Data sources: `MFADevice`, `BackupCode`, `Profile`, `MFALog`, device tables.
  - How to:
    1) Verify enrolled methods and rotate/disable as needed.
    2) Inspect recent logs to validate user claims.
    3) Review device fingerprint risk and session list; revoke if suspicious.

- __Session Management__ (`session_management.html`)
  - Active sessions count, session list with device/IP, revoke controls.
  - Policy: session timeout and remember‑me behavior overview.

### Logs and Reporting

- __Logs List__ (`logs_list.html`)
  - Advanced filters toolbar: outcome, method, event, user, IP, date range.
  - AJAX pagination, CSV export, and detail overlays where applicable.

  - Purpose: Deep dive on authentication events for investigations.
  - Data sources: `MFALog` queries in `mfa/views.py` with filter params; rendered server‑side, interactive via JS.
  - How to:
    1) Set filters (e.g., Outcome=Failures, Method=TOTP, From/To for the window).
    2) Apply to update list; Export CSV for offline analysis.
    3) Click a row (if enabled) to view details and related events.

- __Admin Statistics__ (`admin_statistics.html`)
  - Aggregated stats across the system: auth counts, failure hotspots, top methods.
  - Comparison widgets (week‑over‑week/month‑over‑month).

- __Enterprise Reporting__ (`enterprise_reporting.html`)
  - Executive dashboards and compliance summaries (SOX/GDPR/HIPAA/ISO27001).
  - Export PDF/CSV packs; schedule generation hooks.

- __Compliance Report__ (`compliance_report.html`)
  - Framework-specific status (SOX, GDPR, HIPAA, ISO 27001) with pass/fail checks.
  - Evidence links and remediation guidance; exportable compliance packet.

- __Report Settings__ (`report_settings.html`)
  - Configure scheduled Security Summary email: enable, frequency, recipients, CSV range.
  - Trigger “Send Now”; view last/next send timestamps.

  - Purpose: Automate weekly/monthly security reporting.
  - Data sources: `MFASettings` singleton; management command `send_security_summary`.
  - How to:
    1) Enable, set frequency (days), and recipients.
    2) Choose CSV window; click Send Now to test.

### Platform and Integrations

- __API Management__ (`api_management.html`)
  - API keys, rate limits, webhooks, and documentation links.
  - Create/rotate keys and set per‑key quotas.

  - Purpose: Control programmatic access and integrations.
  - Data sources: API keys table; webhook endpoints configured in settings.
  - How to: Create a key, copy securely, set quotas; configure webhook targets.

- __Backup & Recovery__ (`backup_recovery.html`)
  - Backups status, last snapshot time, retention window.
  - Restore drill and export artifacts.

- __Workflow Automation__ (`workflow_automation.html`)
  - Build automations for alerts/incidents (if‑this‑then‑that rules).
  - Connectors: email, webhook, ticketing.

- __Notification Center__ (`notification_center.html`)
  - Recent admin‑facing notifications and alert rules.
  - Per‑channel enable/disable and severity thresholds.

### Settings and Access

- __Admin Settings__ (`admin_settings.html`)
  - Global toggles (enable/disable methods), environment flags, brand settings.
  - Persistence to `MFASettings` singleton; guarded actions for safety.

  - Purpose: Central control of MFA behavior and branding.
  - Data sources: `MFASettings.load()`; forms protected for staff.
  - How to: Adjust toggles and save; changes apply immediately to flows.

- __Organization Management__ (`organization_management.html`)
  - Tenants/hierarchy view, role assignments, and access scopes.
  - Team membership and delegated admin controls.

### Admin Login and MFA

- __Admin Login__ (`admin_login.html`)
  - Admin‑specific login form with brand and security key hints.

- __Admin Verify Email__ (`admin_verify_email.html`)
  - Email OTP verification to protect admin sign‑in.
  - Uses the same hardened OTP rules and UI as user flows.

### Tips

- __Filtering__: Use the toolbar filters to quickly narrow results; most lists support Enter‑to‑apply.
- __Exports__: Charts often include a “Download PNG”; tables commonly offer CSV export.
- __Accessibility__: Inputs and buttons include proper labels/titles; keyboard navigation is supported.

### Endpoints map (quick reference)

- __Real‑Time Monitoring__: `mfa/ajax_views_realtime.py` → `live_activity_feed`, `live_system_stats` (`mfa/urls.py` names)
- __ML Risk Engine__: `mfa/views_admin_api.py` → `admin_api_ml_summary`, `admin_api_risk_distribution`
- __Logs List__: server‑rendered via `mfa/views.py` with filter params (`outcome`, `method`, `event`, `user`, `ip`, `from`, `to`)

