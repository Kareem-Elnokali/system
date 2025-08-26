from django.db import migrations











def gen_key():



    import random



    alphabet = 'abcdefghjkmnpqrstuvwxyz23456789'



    return ''.join(random.choice(alphabet) for _ in range(6))











def ensure_profiles_and_keys(apps, schema_editor):



    User = apps.get_model('auth', 'User')



    Profile = apps.get_model('mfa', 'Profile')







    existing = set(Profile.objects.values_list('user_id', flat=True))



    users = User.objects.all().only('id')









    to_create = [Profile(user_id=u.id) for u in users if u.id not in existing]



    if to_create:



        Profile.objects.bulk_create(to_create, ignore_conflicts=True)









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



        ('mfa', '0012_profile_safety_key'),



    ]







    operations = [



        migrations.RunPython(ensure_profiles_and_keys, reverse_code=noop_reverse),



    ]



