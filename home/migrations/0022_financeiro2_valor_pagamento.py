# Generated by Django 5.1.1 on 2024-12-04 00:02

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0021_alter_financeiro2_semana'),
    ]

    operations = [
        migrations.AddField(
            model_name='financeiro2',
            name='valor_pagamento',
            field=models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True),
        ),
    ]