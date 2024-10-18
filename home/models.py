from django.db import models
from django.contrib.auth.models import User
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
    
class Sala(models.Model):
    id_sala = models.AutoField(primary_key=True)
    cor_sala =  models.CharField(max_length=100)
    numero_sala = models.PositiveIntegerField()
    id_unidade = models.ForeignKey(Unidade, on_delete=models.CASCADE, related_name='salas')

    def __str__(self):
        return f"Sala {self.numero_sala} - {self.cor_sala}"
    
class Paciente(models.Model):
    nome = models.CharField(max_length=100)
    idade = models.CharField(max_length=100)
    rg = models.CharField(max_length=100)
    email = models.EmailField(max_length=100)
    telefone = models.CharField(max_length=100)
    cpf = models.CharField(max_length=100)

class ConfirmacaoConsulta(models.Model):
    dia_semana = models.CharField(max_length=100)
    periodo_atendimento = models.CharField(max_length=100)
    data = models.DateField()
    horario_inicio = models.TimeField()
    horario_fim = models.TimeField()
    forma_pagamento = models.CharField(max_length=100)
    valor = models.DecimalField(max_digits=10, decimal_places=2)
    observacoes = models.CharField(max_length=100)

class Disponibilidade(models.Model):
    data = models.DateField()
    hora_inicio = models.TimeField()
    hora_fim = models.TimeField()

class PsicoConfirmarConsulta(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    confirmacao_consulta = models.ForeignKey(ConfirmacaoConsulta, on_delete=models.CASCADE)

class PsicoDisponibilidade(models.Model):
    disponibilidade = models.ForeignKey(Disponibilidade, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

class Consulta(models.Model):
    data = models.DateField()
    horario_inicio = models.TimeField()
    horario_fim = models.TimeField()
    observacao = models.CharField(max_length=100)
    sala_atendimento = models.ForeignKey(Sala, on_delete=models.CASCADE)
    paciente = models.ForeignKey(Paciente, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
