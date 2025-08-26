







from django.db import migrations, models











class Migration(migrations.Migration):







    dependencies = [



        ('mfa', '0010_update_site_domain'),



    ]







    operations = [



        migrations.AddField(



            model_name='mfasettings',



            name='enable_backup_codes',



            field=models.BooleanField(default=True),



        ),



    ]



