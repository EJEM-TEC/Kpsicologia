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
    rg = models.CharField(max_length=100)

    def __str__(self):
        return self.nome

class Unidade(models.Model):
    id_unidade = models.AutoField(primary_key=True)
    nome_unidade = models.CharField(max_length=100)
    endereco_unidade = models.CharField(max_length=100)
    CEP_unidade = models.CharField(max_length=100)
    

    def __str__(self):
        return self.nome   
    
class Sala(models.Model):
    id_sala = models.AutoField(primary_key=True)
    cor_sala = models.CharField(max_length=16)
    #numero_sala = models.PositiveIntegerField()
    numero_sala = models.CharField(max_length=100)
    id_unidade = models.ForeignKey(Unidade, on_delete=models.CASCADE, related_name='salas')
    horario_inicio = models.TimeField()
    horario_fim = models.TimeField()

    def __str__(self):
        return f"Sala {self.numero_sala} - {self.cor_sala}"
    
class Psicologa(models.Model):
    nome=models.CharField(max_length=100)
    cor = models.CharField(max_length=100)
    email=models.CharField(max_length=100)
    abordagem = models.CharField(max_length=100)
    senha=models.CharField(max_length=100)
    ultima_atualizacao_agenda = models.DateField(auto_now=True)
    
    def __str__(self):
        return self.usuario.username
    
class Paciente(models.Model):
    id = models.AutoField(primary_key=True)
    nome = models.CharField(max_length=100)
    idade = models.CharField(max_length=100)
    telefone = models.CharField(max_length=100)
    nome_responsavel = models.CharField(max_length=100)
    valor = models.DecimalField(max_digits=10, decimal_places=3)
    periodo = models.CharField(max_length=100, default="semanal")
    deletado = models.BooleanField(default=False)
    data_deletado_psico = models.DateField(null=True, blank=True)
    motivo_deletado_psico = models.CharField(max_length=100, null=True, blank=True)
    data_inspec_admin = models.DateField(auto_now_add=True)
    obs_admin = models.CharField(max_length=100, null=True, blank=True)


class Especialidade(models.Model):
    id = models.AutoField(primary_key=True)
    especialidade = models.CharField(max_length=100)


class Disponibilidade(models.Model):
    dia_semana = models.CharField(max_length=100)
    hora = models.TimeField()
    psicologa = models.ForeignKey(Psicologa, on_delete=models.CASCADE)

    
class Consulta(models.Model):
    psicologo = models.ForeignKey(Psicologa, on_delete=models.CASCADE, null=True)
    Paciente = models.ForeignKey(Paciente, on_delete=models.CASCADE, null=True)
    horario = models.TimeField()
    dia_semana = models.CharField(max_length=100)
    semanal = models.CharField(max_length=32, null=True)
    quinzenal = models.CharField(max_length=32, null=True)
    sala=models.ForeignKey(Sala, on_delete=models.CASCADE)
    METODO_CHOICES = [
        ('padrao', 'Padrão'),
        ('livre', 'Livre'),
        ('fechado', 'Fechado'),
    ]
    
    metodo = models.CharField(
        max_length=20,
        choices=METODO_CHOICES,
        default='padrao',
        help_text='Método de agendamento para este horário'
    )

class Despesas(models.Model):
    motivo = models.CharField(max_length=100, null=True, blank=True)
    valor = models.DecimalField(max_digits=10, decimal_places=2)
    data = models.DateField()
    

class Consulta_Online(models.Model):
    psicologo = models.ForeignKey(Psicologa, on_delete=models.CASCADE, null=True)
    Paciente = models.ForeignKey(Paciente, on_delete=models.CASCADE, null=True)
    horario = models.TimeField()
    dia_semana = models.CharField(max_length=100)
    semanal = models.CharField(max_length=32, null=True)
    quinzenal = models.CharField(max_length=32, null=True)
    ultima_atualizacao = models.DateTimeField(auto_now=True)

class Financeiro(models.Model):
    dia_semana = models.CharField(max_length=32, blank=True, null=True)
    periodo_atendimento = models.CharField(max_length=32, blank=True, null=True)
    psicologa = models.ForeignKey(Psicologa, on_delete=models.CASCADE)
    paciente = models.ForeignKey(Paciente, on_delete=models.CASCADE)
    data = models.DateField(null=True, blank=True)
    presenca = models.CharField(max_length=32, null=True, blank=True)
    horario = models.TimeField(null=True, blank=True)
    forma = models.CharField(max_length=32, null=True, blank=True)
    observacoes = models.CharField(max_length=32, null=True, blank=True)
    valor = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    semana = models.IntegerField()  # Semana dentro do mês
    valor_pagamento = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    data_pagamento = models.DateField(null=True, blank=True)
    modalidade = models.CharField(max_length=32, null=True, blank=True)
    bloqueada = models.BooleanField(default=False)
    sala = models.ForeignKey(Sala, on_delete=models.CASCADE, null=True, blank=True)


class Publico(models.Model):
    id = models.AutoField(primary_key=True)
    publico = models.CharField(max_length=100, blank=True, null=True)


class PublicoPsico(models.Model):
    psico = models.ForeignKey(Psicologa, on_delete=models.CASCADE)
    publico = models.ForeignKey(Publico, on_delete=models.CASCADE)


class EspecialidadePsico(models.Model):
    especialidade = models.ForeignKey(Especialidade, on_delete=models.CASCADE)
    psico = models.ForeignKey(Psicologa, on_delete=models.CASCADE)

class UnidadePsico(models.Model):
    unidade = models.ForeignKey(Unidade, on_delete=models.CASCADE)
    psico = models.ForeignKey(Psicologa, on_delete=models.CASCADE)




    