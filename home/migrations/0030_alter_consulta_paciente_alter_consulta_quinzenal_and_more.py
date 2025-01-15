# Generated by Django 5.1.1 on 2025-01-15 15:45

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0029_alter_consulta_paciente_alter_consulta_quinzenal_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='consulta',
            name='Paciente',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='home.paciente'),
        ),
        migrations.AlterField(
            model_name='consulta',
            name='quinzenal',
            field=models.CharField(max_length=32, null=True),
        ),
        migrations.AlterField(
            model_name='consulta',
            name='semanal',
            field=models.CharField(max_length=32, null=True),
        ),
    ]
