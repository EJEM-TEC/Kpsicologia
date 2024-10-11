from django.db import models

# Create your models here.
# aqui
class Usuario(models.Model):
    username = models.CharField(max_length=100)
    idade = models.PositiveIntegerField()
    email = models.EmailField()
    cargo = models.CharField(max_length=100)
    telefone = models.CharField(max_length=15)  # Formato para incluir DDD
    rg = models.CharField(max_length=12)

    def __str__(self):
        return self.nome
