







from django.db import migrations, models











class Migration(migrations.Migration):







    dependencies = [



        ('mfa', '0004_mfalog'),



    ]







    operations = [



        migrations.AddField(



            model_name='mfasettings',



            name='mfa_required',



            field=models.BooleanField(default=True, help_text='If checked, all users will be required to set up at least one MFA method to log in.'),



        ),



        migrations.AlterField(



            model_name='mfasettings',



            name='enable_backup_codes',



            field=models.BooleanField(default=True, verbose_name='Enable Backup Codes'),



        ),



        migrations.AlterField(



            model_name='mfasettings',



            name='enable_email',



            field=models.BooleanField(default=True, verbose_name='Enable Email OTP'),



        ),



        migrations.AlterField(



            model_name='mfasettings',



            name='enable_passkeys',



            field=models.BooleanField(default=False, verbose_name='Enable Passkeys (WebAuthn)'),



        ),



        migrations.AlterField(



            model_name='mfasettings',



            name='enable_sms',



            field=models.BooleanField(default=False, verbose_name='Enable SMS'),



        ),



        migrations.AlterField(



            model_name='mfasettings',



            name='enable_totp',



            field=models.BooleanField(default=True, verbose_name='Enable Authenticator (TOTP)'),



        ),



    ]



