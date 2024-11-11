from django.db import models
from django.contrib.auth.models import User
from django import forms
from django.utils import timezone
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

class Psicologo(models.Model):
    id = models.AutoField(primary_key=True)
    nome=models.CharField(max_length=32)
    cor = models.CharField(max_length=16)
    
    def __str__(self):
        return self.usuario.username 

class Unidade(models.Model):
    id_unidade = models.AutoField(primary_key=True)
    nome_unidade = models.CharField(max_length=100)
    endereco_unidade = models.CharField(max_length=100)
    CEP_unidade = models.IntegerField()
    

    def __str__(self):
        return self.nome   
    
class Sala(models.Model):
    id_sala = models.AutoField(primary_key=True)
    cor_sala = models.CharField(
        max_length=20,
        choices=[
            ('red', 'Vermelho'),
            ('green', 'Verde'),
            ('blue', 'Azul'),
            ('black', 'Preto'),
            ('white', 'Branco'),
            ('gray', 'Cinza'),
            ('yellow', 'Amarelo'),
            ('cyan', 'Ciano'),
            ('magenta', 'Magenta'),
        ],
        default='white'
    )
    #numero_sala = models.PositiveIntegerField()
    numero_sala = models.CharField(max_length=100)

    id_unidade = models.ForeignKey(Unidade, on_delete=models.CASCADE, related_name='salas')

    def __str__(self):
        return f"Sala {self.numero_sala} - {self.cor_sala}"
    
class Psicologa(models.Model):
    nome=models.CharField(max_length=32)
    cor = models.CharField(max_length=16)
    email=models.CharField(max_length=100)
    senha=models.CharField(max_length=100)
    
    def __str__(self):
        return self.usuario.username
    
class Paciente(models.Model):
    id = models.AutoField(primary_key=True)
    nome = models.CharField(max_length=100)
    idade = models.IntegerField()
    rg = models.IntegerField()
    email = models.EmailField(max_length=100)
    telefone = models.IntegerField()
    cpf = models.IntegerField()
    periodo = models.CharField(max_length=100, default="semanal")


class ConfirmacaoConsulta(models.Model):
    dia_semana = models.CharField(max_length=100)
    periodo_atendimento = models.CharField(max_length=100) 
    data = models.DateField() 
    horario_inicio = models.TimeField()
    confirmacao = models.CharField(max_length=100)
    forma_pagamento = models.CharField(max_length=100) 
    valor = models.DecimalField(max_digits=10, decimal_places=2)
    observacoes = models.CharField(max_length=100)
    paciente = models.ForeignKey(Paciente, on_delete=models.CASCADE)
    psicologa = models.ForeignKey(Psicologa, on_delete=models.CASCADE)


class Disponibilidade(models.Model):
    id = models.AutoField(primary_key=True)
    data = models.DateField()
    hora_inicio = models.TimeField()
    hora_fim = models.TimeField()

class ConfirmacaoConsulta(models.Model):
    data = models.DateTimeField() 
    psicologo = models.ForeignKey(Psicologa, on_delete=models.CASCADE)
    confirmacao = models.CharField(max_length=100)
    forma_pagamento = models.CharField(max_length=100) 
    valor = models.DecimalField(max_digits=10, decimal_places=2)
    observacoes = models.CharField(max_length=100)
    paciente = models.ForeignKey(Paciente, on_delete=models.CASCADE)

class PsicoConfirmarConsulta(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    confirmacao_consulta = models.ForeignKey(ConfirmacaoConsulta, on_delete=models.CASCADE)
    dia_semana = models.CharField(max_length=100)
    hora = models.TimeField()
    livre_ocupado = models.CharField(max_length=100)
    
class AgendaPsico(models.Model):
    dia_semana = models.CharField(max_length=100)
    hora = models.TimeField()
    livre_ocupado = models.CharField(max_length=100)

# class PsicoConfirmarConsulta(models.Model):
#     user = models.ForeignKey(User, on_delete=models.CASCADE)
#     confirmacao_consulta = models.ForeignKey(ConfirmacaoConsulta, on_delete=models.CASCADE)

class PsicoDisponibilidade(models.Model):
    id = models.AutoField(primary_key=True)
    disponibilidade = models.ForeignKey(Disponibilidade, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

#class Consulta(models.Model):
    #id_consulta = models.AutoField(primary_key=True)
    #data = models.DateField()
    #horario_inicio = models.TimeField()
    #horario_fim = models.TimeField()
    #observacao = models.CharField(max_length=100)
    #sala_atendimento = models.ForeignKey(Sala, on_delete=models.CASCADE)
    #paciente = models.ForeignKey(Paciente, on_delete=models.CASCADE)
    #user = models.ForeignKey(User, on_delete=models.CASCADE)


    disponibilidade = models.ForeignKey(AgendaPsico, on_delete=models.CASCADE)
    user = models.ForeignKey(Psicologa, on_delete=models.CASCADE)
    
class Consulta(models.Model):
    psicologo = models.ForeignKey(Psicologa, on_delete=models.CASCADE)
    Paciente = models.ForeignKey(Paciente, on_delete=models.CASCADE)
    horario = models.TimeField()
    dia_semana = models.CharField(max_length=100)
    semanal = models.CharField(max_length=32)
    quinzenal = models.CharField(max_length=32)
    sala=models.ForeignKey(Sala, on_delete=models.CASCADE)


class Disponibilidade(models.Model):
    id = models.AutoField(primary_key=True)
    dia_semana = models.CharField(max_length=100)
    hora = models.TimeField()
    livre_ocupado = models.CharField(max_length=100)
    
class AgendaPsico(models.Model):
    dia_semana = models.CharField(max_length=100)
    hora = models.TimeField()
    livre_ocupado = models.CharField(max_length=100)

# class PsicoConfirmarConsulta(models.Model):
#     user = models.ForeignKey(User, on_delete=models.CASCADE)
#     confirmacao_consulta = models.ForeignKey(ConfirmacaoConsulta, on_delete=models.CASCADE)

class PsicoDisponibilidade(models.Model):
    disponibilidade = models.ForeignKey(AgendaPsico, on_delete=models.CASCADE)
    user = models.ForeignKey(Psicologo, on_delete=models.CASCADE)

#class Consulta(models.Model):
    #id_consulta = models.AutoField(primary_key=True)
    #data = models.DateField()
    #horario_inicio = models.TimeField()
    #horario_fim = models.TimeField()
    #observacao = models.CharField(max_length=100)
    #sala_atendimento = models.ForeignKey(Sala, on_delete=models.CASCADE)
    #paciente = models.ForeignKey(Paciente, on_delete=models.CASCADE)
    #user = models.ForeignKey(User, on_delete=models.CASCADE)

# class Psicologo(models.Model):
#     nome=models.CharField(max_length=32)
#     tempo_consulta = models.DurationField(help_text="Duração de cada consulta (ex: 00:30:00 para 30 minutos)")
#     consultas_por_dia = models.PositiveIntegerField(help_text="Número máximo de consultas por dia")
#     horario_inicio = models.TimeField(help_text="Horário de início das consultas (ex: 09:00)")
#     cor = models.CharField(max_length=16)
    
#     def __str__(self):
#         return self.usuario.username
    
class Consulta(models.Model):
    psicologo = models.ForeignKey(Psicologa, on_delete=models.CASCADE)
    Paciente = models.ForeignKey(Paciente, on_delete=models.CASCADE)
    horario = models.TimeField()
    dia_semana = models.CharField(max_length=100)
    repeticao = models.CharField(max_length=32)
    semanal = models.CharField(max_length=32)
    quinzenal = models.CharField(max_length=32)
    sala=models.ForeignKey(Sala, on_delete=models.CASCADE)

    