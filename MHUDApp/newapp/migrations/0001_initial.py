# Generated by Django 4.2.2 on 2024-04-09 18:16

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='AddUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('Username', models.CharField(max_length=100)),
                ('Email', models.CharField(max_length=100)),
                ('Password', models.CharField(max_length=100)),
            ],
        ),
    ]
