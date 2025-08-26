







from django.db import migrations











class Migration(migrations.Migration):







    dependencies = [



        ('mfa', '0006_remove_mfasettings_mfa_required_and_more'),



    ]







    operations = [



        migrations.RemoveField(



            model_name='mfasettings',



            name='enable_backup_codes',



        ),



    ]



