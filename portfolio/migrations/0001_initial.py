# Generated by Django 4.0.5 on 2022-06-09 18:36

from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Project',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=100)),
                ('descriprion', models.CharField(max_length=250)),
                ('image', models.ImageField(upload_to='portfolio/images/')),
                ('video', models.FileField(upload_to='portfolio/videos/')),
                ('url', models.URLField(blank=True)),
            ],
        ),
    ]
