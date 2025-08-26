







from django.db import migrations, models











class Migration(migrations.Migration):







    dependencies = [



        ('mfa', '0005_mfasettings_mfa_required_and_more'),



    ]







    operations = [



        migrations.RemoveField(



            model_name='mfasettings',



            name='mfa_required',



        ),



        migrations.AlterField(



            model_name='mfasettings',



            name='enable_backup_codes',



            field=models.BooleanField(default=True),



        ),



        migrations.AlterField(



            model_name='mfasettings',



            name='enable_email',



            field=models.BooleanField(default=True),



        ),



        migrations.AlterField(



            model_name='mfasettings',



            name='enable_passkeys',



            field=models.BooleanField(default=True),



        ),



        migrations.AlterField(



            model_name='mfasettings',



            name='enable_sms',



            field=models.BooleanField(default=True),



        ),



        migrations.AlterField(



            model_name='mfasettings',



            name='enable_totp',



            field=models.BooleanField(default=True),



        ),



    ]



