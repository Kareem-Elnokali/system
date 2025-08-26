







import django.db.models.deletion



import django.utils.timezone



from django.conf import settings



from django.db import migrations, models











class Migration(migrations.Migration):







    dependencies = [



        ('mfa', '0003_mfasettings_always_show_method_picker'),



        migrations.swappable_dependency(settings.AUTH_USER_MODEL),



    ]







    operations = [



        migrations.CreateModel(



            name='MFALog',



            fields=[



                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),



                ('event', models.CharField(choices=[('choose_method', 'Choose Method'), ('email_code_sent', 'Email Code Sent'), ('email_verify_success', 'Email Verify Success'), ('email_verify_failure', 'Email Verify Failure'), ('totp_verify_success', 'TOTP Verify Success'), ('totp_verify_failure', 'TOTP Verify Failure'), ('backup_codes_generated', 'Backup Codes Generated'), ('backup_code_used', 'Backup Code Used'), ('totp_linked', 'TOTP Linked'), ('totp_unlinked', 'TOTP Unlinked')], max_length=64)),



                ('method', models.CharField(blank=True, max_length=32)),



                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),



                ('user_agent', models.TextField(blank=True)),



                ('details', models.TextField(blank=True)),



                ('created_at', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),



                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='mfa_logs', to=settings.AUTH_USER_MODEL)),



            ],



            options={



                'ordering': ['-created_at'],



                'indexes': [models.Index(fields=['event', 'created_at'], name='mfa_mfalog_event_0f7dc4_idx'), models.Index(fields=['user', 'created_at'], name='mfa_mfalog_user_id_007151_idx')],



            },



        ),



    ]



