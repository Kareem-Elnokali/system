from django.db import migrations



import os











def create_google_socialapp(apps, schema_editor):



    Site = apps.get_model('sites', 'Site')



    SocialApp = apps.get_model('socialaccount', 'SocialApp')







    client_id = os.getenv('GOOGLE_CLIENT_ID')



    secret = os.getenv('GOOGLE_CLIENT_SECRET')









    if not client_id or not secret:



        return









    site, _ = Site.objects.get_or_create(id=1, defaults={'domain': 'localhost:8000', 'name': 'localhost'})







    app, created = SocialApp.objects.get_or_create(



        provider='google',



        name='Google',



        defaults={'client_id': client_id, 'secret': secret, 'key': ''},



    )



    if not created:





        changed = False



        if app.client_id != client_id:



            app.client_id = client_id



            changed = True



        if app.secret != secret:



            app.secret = secret



            changed = True



        if changed:



            app.save(update_fields=['client_id', 'secret'])









    if site not in app.sites.all():



        app.sites.add(site)











def remove_google_socialapp(apps, schema_editor):



    SocialApp = apps.get_model('socialaccount', 'SocialApp')



    SocialApp.objects.filter(provider='google', name='Google').delete()











class Migration(migrations.Migration):



    dependencies = [



        ('mfa', '0008_profile'),



        ('sites', '0002_alter_domain_unique'),



        ('socialaccount', '0001_initial'),



    ]







    operations = [



        migrations.RunPython(create_google_socialapp, remove_google_socialapp),



    ]



