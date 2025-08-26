







from django.db import migrations, models











class Migration(migrations.Migration):







    dependencies = [



        ('mfa', '0001_initial'),



    ]







    operations = [



        migrations.CreateModel(



            name='MFASettings',



            fields=[



                ('id', models.PositiveSmallIntegerField(default=1, editable=False, primary_key=True, serialize=False)),



                ('enable_totp', models.BooleanField(default=True)),



                ('enable_email', models.BooleanField(default=True)),



                ('enable_backup_codes', models.BooleanField(default=True)),



                ('enable_passkeys', models.BooleanField(default=False)),



                ('enable_sms', models.BooleanField(default=False)),



                ('updated_at', models.DateTimeField(auto_now=True)),



            ],



            options={



                'verbose_name': 'MFA Settings',



                'verbose_name_plural': 'MFA Settings',



            },



        ),



    ]



