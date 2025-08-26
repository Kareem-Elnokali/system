from .utils import recaptcha_site_key, turnstile_site_key
def captcha_keys(request):
    """Provide CAPTCHA keys globally to templates.
    Prefer Google reCAPTCHA when present; otherwise provide Turnstile key.
    """
    site = recaptcha_site_key()
    return {
        'recaptcha_site_key': site,
        'turnstile_site_key': None if site else turnstile_site_key(),
    }
