# Generated by Django 5.1.1 on 2024-11-07 00:08

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='psicologa',
            name='consultas_por_dia',
        ),
        migrations.RemoveField(
            model_name='psicologa',
            name='horario_inicio',
        ),
        migrations.RemoveField(
            model_name='psicologa',
            name='tempo_consulta',
        ),
    ]
