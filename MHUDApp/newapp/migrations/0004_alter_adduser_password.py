# Generated by Django 4.2.2 on 2024-04-11 14:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('newapp', '0003_adduser_delete_user'),
    ]

    operations = [
        migrations.AlterField(
            model_name='adduser',
            name='Password',
            field=models.BinaryField(max_length=100),
        ),
    ]
