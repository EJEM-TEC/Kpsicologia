# Generated by Django 5.1.1 on 2024-11-27 14:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0017_financeiro2'),
    ]

    operations = [
        migrations.AddField(
            model_name='financeiro2',
            name='horario',
            field=models.TimeField(blank=True, null=True),
        ),
    ]
