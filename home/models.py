from django.db import models

# Create your models here.
# aqui
class Usuario(models.Model):
    id_usuario = models.AutoField(primary_key=True)
    username = models.CharField(max_length=100)
    idade = models.PositiveIntegerField()
    email = models.EmailField()
    cargo = models.CharField(max_length=100)
    telefone = models.IntegerField()
    rg = models.CharField(max_length=12)

    def __str__(self):
        return self.nome
    
class Unidade(models.Model):
    id_unidade = models.AutoField(primary_key=True)
    nome_unidade = models.CharField(max_length=100)
    endereco_unidade = models.CharField(max_length=100)
    CEP_unidade = models.IntegerField()

    def __str__(self):
        return self.nome