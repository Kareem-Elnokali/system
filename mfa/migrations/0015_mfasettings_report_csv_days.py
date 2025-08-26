from django.db import migrations, models











class Migration(migrations.Migration):







    dependencies = [



        ('mfa', '0014_mfasettings_report_enabled_and_more'),



    ]







    operations = [



        migrations.AddField(



            model_name='mfasettings',



            name='report_csv_days',



            field=models.PositiveSmallIntegerField(default=7),



        ),



    ]



