







from django.db import migrations, models











class Migration(migrations.Migration):







    dependencies = [



        ('mfa', '0013_backfill_profiles_and_keys'),



    ]







    operations = [



        migrations.AddField(



            model_name='mfasettings',



            name='report_enabled',



            field=models.BooleanField(default=False),



        ),



        migrations.AddField(



            model_name='mfasettings',



            name='report_frequency_days',



            field=models.PositiveSmallIntegerField(default=7),



        ),



        migrations.AddField(



            model_name='mfasettings',



            name='report_last_sent_at',



            field=models.DateTimeField(blank=True, null=True),



        ),



        migrations.AddField(



            model_name='mfasettings',



            name='report_next_send_at',



            field=models.DateTimeField(blank=True, null=True),



        ),



        migrations.AddField(



            model_name='mfasettings',



            name='report_recipients',



            field=models.TextField(blank=True, default=''),



        ),



        migrations.AlterField(



            model_name='profile',



            name='safety_key',



            field=models.CharField(blank=True, max_length=8, null=True, unique=True),



        ),



    ]



