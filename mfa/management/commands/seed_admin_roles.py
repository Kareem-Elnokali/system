from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group

DEFAULT_GROUPS = [
    'Security Admin',
    'Analyst',
    'Compliance',
    'Support',
]

class Command(BaseCommand):
    help = "Create default admin role groups for least-privilege access"

    def handle(self, *args, **options):
        created = 0
        for name in DEFAULT_GROUPS:
            grp, was_created = Group.objects.get_or_create(name=name)
            created += 1 if was_created else 0
        if created:
            self.stdout.write(self.style.SUCCESS(f"Created {created} groups."))
        else:
            self.stdout.write("All default groups already exist.")
