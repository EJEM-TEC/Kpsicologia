# Generated by Django 5.1.2 on 2024-10-17 21:10

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0003_unidade'),
    ]

    operations = [
        migrations.CreateModel(
            name='Sala',
            fields=[
                ('id_sala', models.AutoField(primary_key=True, serialize=False)),
                ('cor_sala', models.CharField(max_length=100)),
                ('numero_sala', models.PositiveIntegerField()),
                ('codigo_sala', models.CharField(max_length=100)),
                ('id_unidade', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='salas', to='home.unidade')),
            ],
        ),
    ]