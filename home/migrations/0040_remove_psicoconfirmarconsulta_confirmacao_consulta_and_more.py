# Generated by Django 5.1.1 on 2025-04-08 18:33

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0039_financeiro_bloqueada'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='psicoconfirmarconsulta',
            name='confirmacao_consulta',
        ),
        migrations.RemoveField(
            model_name='psicoconfirmarconsulta',
            name='user',
        ),
        migrations.AddField(
            model_name='financeiro',
            name='sala',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='home.sala'),
        ),
        migrations.DeleteModel(
            name='ConfirmacaoConsulta',
        ),
        migrations.DeleteModel(
            name='PsicoConfirmarConsulta',
        ),
    ]
