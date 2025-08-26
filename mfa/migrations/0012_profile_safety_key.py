from django.db import migrations, models



import django.db.models.deletion











def gen_key():





    import random



    alphabet = 'abcdefghjkmnpqrstuvwxyz23456789'



    return ''.join(random.choice(alphabet) for _ in range(6))











def backfill_safety_keys(apps, schema_editor):



    Profile = apps.get_model('mfa', 'Profile')



    for profile in Profile.objects.filter(safety_key__isnull=True):



        key = gen_key()





        tries = 0



        while Profile.objects.filter(safety_key=key).exists() and tries < 5:



            key = gen_key()



            tries += 1



        profile.safety_key = key



        profile.save(update_fields=['safety_key'])











def noop_reverse(apps, schema_editor):



    pass











class Migration(migrations.Migration):







    dependencies = [



        ('mfa', '0011_mfasettings_enable_backup_codes'),



    ]







    operations = [



        migrations.AddField(



            model_name='profile',



            name='safety_key',



            field=models.CharField(max_length=16, blank=True, null=True, unique=True),



        ),



        migrations.RunPython(backfill_safety_keys, reverse_code=noop_reverse),



    ]



