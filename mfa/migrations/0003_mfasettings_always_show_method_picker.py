







from django.db import migrations, models











class Migration(migrations.Migration):







    dependencies = [



        ('mfa', '0002_mfasettings'),



    ]







    operations = [



        migrations.AddField(



            model_name='mfasettings',



            name='always_show_method_picker',



            field=models.BooleanField(default=True),



        ),



    ]



