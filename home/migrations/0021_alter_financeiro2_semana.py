# Generated by Django 5.1.1 on 2024-12-01 22:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0020_financeiro2_semana'),
    ]

    operations = [
        migrations.AlterField(
            model_name='financeiro2',
            name='semana',
            field=models.IntegerField(default=1),
            preserve_default=False,
        ),
    ]