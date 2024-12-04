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
    abordagem = models.CharField(max_length=100)
    senha=models.CharField(max_length=100)
    
    def __str__(self):
        return self.usuario.username
    
class Paciente(models.Model):
    id = models.AutoField(primary_key=True)
    nome = models.CharField(max_length=100)
    idade = models.CharField(max_length=100)
    telefone = models.IntegerField()
    nome_responsavel = models.CharField(max_length=100)
    valor = models.DecimalField(max_digits=10, decimal_places=3)
    tipo_atendimento = models.CharField(max_length=100)
    periodo = models.CharField(max_length=100, default="semanal")


class Especialidade(models.Model):
    id = models.AutoField(primary_key=True)
    especialidade = models.CharField(max_length=100)


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



class PsicoConfirmarConsulta(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    confirmacao_consulta = models.ForeignKey(ConfirmacaoConsulta, on_delete=models.CASCADE)
    dia_semana = models.CharField(max_length=100)
    hora = models.TimeField()
    livre_ocupado = models.CharField(max_length=100)
    
    
class Consulta(models.Model):
    psicologo = models.ForeignKey(Psicologa, on_delete=models.CASCADE)
    Paciente = models.ForeignKey(Paciente, on_delete=models.CASCADE)
    horario = models.TimeField()
    dia_semana = models.CharField(max_length=100)
    semanal = models.CharField(max_length=32)
    quinzenal = models.CharField(max_length=32)
    sala=models.ForeignKey(Sala, on_delete=models.CASCADE)

class Financeiro2(models.Model):
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

class Financeiro(models.Model):
    psicologa = models.ForeignKey(Psicologa, on_delete=models.CASCADE, null=True)
    valor_previsto = models.DecimalField(max_digits=10, decimal_places=2)
    valor_pendente = models.DecimalField(max_digits=10, decimal_places=2)
    valor_acertado = models.DecimalField(max_digits=10, decimal_places=2)
    valor_total= models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    qtd_pacientes = models.PositiveIntegerField()
    desistencias_atendidos = models.PositiveIntegerField()
    qtd_marcacoes = models.PositiveIntegerField()
    desistencias_novos = models.PositiveIntegerField()


    def save(self, *args, **kwargs):
        self.valor_total = self.valor_previsto + self.valor_pendente + self.valor_acertado
        super().save(*args, **kwargs)


class Publico(models.Model):
    id = models.AutoField(primary_key=True)
    publico = models.CharField(max_length=100, blank=True, null=True)


class PublicoPsico(models.Model):
    psico = models.ForeignKey(Psicologa, on_delete=models.CASCADE)
    publico = models.ForeignKey(Publico, on_delete=models.CASCADE)


class EspecialidadePsico(models.Model):
    especialidade = models.ForeignKey(Especialidade, on_delete=models.CASCADE)
    psico = models.ForeignKey(Psicologa, on_delete=models.CASCADE)




    