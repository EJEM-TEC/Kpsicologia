# Generated by Django 5.1.1 on 2024-11-11 14:58

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0004_alter_consulta_horario'),
    ]

    operations = [
        migrations.AlterField(
            model_name='consulta',
            name='psicologo',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='home.psicologa'),
        ),
    ]
