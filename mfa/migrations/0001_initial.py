







import django.db.models.deletion



import django.utils.timezone



from django.conf import settings



from django.db import migrations, models











class Migration(migrations.Migration):







    initial = True







    dependencies = [



        migrations.swappable_dependency(settings.AUTH_USER_MODEL),



    ]







    operations = [



        migrations.CreateModel(



            name='BackupCode',



            fields=[



                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),



                ('code_hash', models.CharField(max_length=64, unique=True)),



                ('used', models.BooleanField(default=False)),



                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),



                ('used_at', models.DateTimeField(blank=True, null=True)),



                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='mfa_backup_codes', to=settings.AUTH_USER_MODEL)),



            ],



            options={



                'indexes': [models.Index(fields=['user', 'used'], name='mfa_backupc_user_id_f4a2b1_idx')],



            },



        ),



        migrations.CreateModel(



            name='MFADevice',



            fields=[



                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),



                ('name', models.CharField(default='Authenticator', max_length=100)),



                ('secret', models.CharField(editable=False, max_length=64)),



                ('confirmed', models.BooleanField(default=False)),



                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),



                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='mfa_devices', to=settings.AUTH_USER_MODEL)),



            ],



            options={



                'indexes': [models.Index(fields=['user', 'confirmed'], name='mfa_mfadevi_user_id_dabf76_idx')],



                'unique_together': {('user', 'name')},



            },



        ),



    ]



