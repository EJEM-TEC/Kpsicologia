# Generated by Django 4.2.16 on 2024-11-12 20:29

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0007_financeiro'),
    ]

    operations = [
        migrations.AddField(
            model_name='financeiro',
            name='psicologa',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='home.psicologa'),
        ),
    ]