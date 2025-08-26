from django.core.management.base import BaseCommand, CommandError
from django.contrib.sites.models import Site
from allauth.socialaccount.models import SocialApp
class Command(BaseCommand):
    help = 'Creates or updates the Google SocialApp for django-allauth.'
    def add_arguments(self, parser):
        parser.add_argument('client_id', type=str, help='Your Google OAuth client ID.')
        parser.add_argument('client_secret', type=str, help='Your Google OAuth client secret.')
    def handle(self, *args, **options):
        client_id = options['client_id']
        client_secret = options['client_secret']
        self.stdout.write(self.style.SUCCESS('Setting up Google OAuth application...'))
        try:
            site = Site.objects.get(pk=1)
            google_app, created = SocialApp.objects.get_or_create(
                provider='google',
                defaults={
                    'name': 'Google',
                    'client_id': client_id,
                    'secret': client_secret,
                }
            )
            if not created:
                google_app.client_id = client_id
                google_app.secret = client_secret
                google_app.save()
                self.stdout.write(self.style.WARNING('Updated existing Google OAuth app.'))
            else:
                self.stdout.write(self.style.SUCCESS('Created new Google OAuth app.'))
            if not google_app.sites.filter(pk=site.pk).exists():
                google_app.sites.add(site)
                self.stdout.write(f'Associated app with site: {site.domain}')
            self.stdout.write(self.style.SUCCESS('--- Google OAuth Setup Complete ---'))
            self.stdout.write(f'  Provider: {google_app.provider}')
            self.stdout.write(f'  Client ID: {client_id[:10]}...')
            self.stdout.write(f'  Site: {site.domain}')
        except Site.DoesNotExist:
            raise CommandError('Default site (pk=1) does not exist. Please create it in the Django admin.')
        except Exception as e:
            raise CommandError(f'An error occurred: {e}')
