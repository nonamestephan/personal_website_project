# Generated by Django 4.0.5 on 2022-06-09 23:23

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('portfolio', '0002_remove_project_video'),
    ]

    operations = [
        migrations.RenameField(
            model_name='project',
            old_name='descriprion',
            new_name='description',
        ),
        migrations.AlterField(
            model_name='project',
            name='image',
            field=models.ImageField(upload_to='portfolio/images'),
        ),
    ]
