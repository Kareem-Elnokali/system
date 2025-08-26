







from django.db import migrations



from django.conf import settings







def update_site_domain(apps, schema_editor):



    Site = apps.get_model('sites', 'Site')



    site, created = Site.objects.get_or_create(pk=settings.SITE_ID)



    site.domain = getattr(settings, 'SITE_DOMAIN', 'localhost:8000')



    site.name = getattr(settings, 'SITE_NAME', 'MySite')



    site.save()







class Migration(migrations.Migration):







    dependencies = [



        ('mfa', '0009_google_socialapp'),



        ('sites', '0001_initial'),



    ]







    operations = [



        migrations.RunPython(update_site_domain),



    ]



