# Generated by Django 5.1.1 on 2024-12-04 01:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0022_financeiro2_valor_pagamento'),
    ]

    operations = [
        migrations.AddField(
            model_name='financeiro2',
            name='data_pagamento',
            field=models.DateField(blank=True, null=True),
        ),
    ]
