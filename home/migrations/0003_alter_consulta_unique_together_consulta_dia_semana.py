# Generated by Django 5.1.1 on 2024-11-11 14:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0002_alter_confirmacaoconsulta_psicologo'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='consulta',
            unique_together=set(),
        ),
        migrations.AddField(
            model_name='consulta',
            name='dia_semana',
            field=models.CharField(default=1, max_length=100),
            preserve_default=False,
        ),
    ]
