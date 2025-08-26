from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.apps import apps

DEFAULT_GROUPS = {
    'Security Admin': {
        # Full control over MFA app models
        'model_perms': {
            'mfa': ['add', 'change', 'delete', 'view'],
        }
    },
    'Analyst': {
        # Read-only over MFA and logs
        'model_perms': {
            'mfa': ['view'],
        }
    },
    'Compliance': {
        # Read-only + change MFA settings
        'model_perms': {
            'mfa': ['view', 'change'],
        }
    },
    'Support': {
        # Limited: view, change MFADevice and trigger resets
        'model_perms': {
            'mfa': ['view', 'change'],
        }
    },
}

# Helper to get all models within an app label

def get_app_models(app_label: str):
    for model in apps.get_app_config(app_label).get_models():
        yield model


class Command(BaseCommand):
    help = "Seed default RBAC groups with basic permissions (idempotent)."

    def handle(self, *args, **options):
        created_groups = []
        updated_groups = []

        for group_name, cfg in DEFAULT_GROUPS.items():
            group, created = Group.objects.get_or_create(name=group_name)
            if created:
                created_groups.append(group_name)

            # Accumulate permissions
            perms_to_add = []
            model_perms = cfg.get('model_perms', {})
            for app_label, actions in model_perms.items():
                actions_set = set(actions)
                for model in get_app_models(app_label):
                    ct = ContentType.objects.get_for_model(model)
                    for action in actions_set:
                        codename = f"{action}_{model._meta.model_name}"
                        perm = Permission.objects.filter(content_type=ct, codename=codename).first()
                        if perm:
                            perms_to_add.append(perm)

            # Apply permissions (idempotent)
            current_ids = set(group.permissions.values_list('id', flat=True))
            add_ids = [p.id for p in perms_to_add if p.id not in current_ids]
            if add_ids:
                group.permissions.add(*add_ids)
                updated_groups.append(group_name)

        msg_created = f"Created groups: {', '.join(created_groups)}" if created_groups else "No new groups created"
        msg_updated = f"Updated groups: {', '.join(updated_groups)}" if updated_groups else "No group permissions changed"
        self.stdout.write(self.style.SUCCESS(f"RBAC seed complete. {msg_created}. {msg_updated}."))
