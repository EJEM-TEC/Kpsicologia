from decimal import Decimal
from pyexpat.errors import messages
import shutil
from django.shortcuts import get_object_or_404, render, redirect
from django.contrib.auth.views import PasswordResetView, PasswordChangeView, PasswordResetConfirmView
from django.urls import reverse
from home.forms import RegistrationForm, UserPasswordResetForm, UserSetPasswordForm, UserPasswordChangeForm
from django.contrib.auth import logout, authenticate, login as login_django
from django.contrib.auth.decorators import login_required, user_passes_test
from rolepermissions.roles import assign_role
from rolepermissions.decorators import has_role_decorator
from django.contrib.auth.models import User, Group
from django.http import HttpResponse, HttpResponseForbidden
from .models import Psicologa, Usuario, Consulta, Unidade, Sala, Paciente, ConfirmacaoConsulta, Financeiro, EspecialidadePsico, Especialidade, Publico, PublicoPsico, Financeiro2
from rolepermissions.roles import assign_role, get_user_roles, RolesManager
from rolepermissions.exceptions import RoleDoesNotExist
from django.contrib.auth.models import Group
from django.contrib.auth import authenticate, login as login_django
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash
from datetime import timedelta
from django.db.models import Sum
from django.shortcuts import render, get_object_or_404, redirect
from docx import Document
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import os
from django.conf import settings
import tempfile
from decimal import Decimal, InvalidOperation
from django.shortcuts import render
from django.db.models import Q
from datetime import datetime
from django.db.models import F, ExpressionWrapper, DecimalField, Sum
from django.db.models.functions import Coalesce  # Import correto para Coalesce



def handler404(request, exception):
    return render(request, '404.html', status=404)

def handler500(request):
    return render(request, '500.html', status=500)


# Páginas Simples
@login_required(login_url='login1')
def index(request):
    return render(request, 'pages/index.html', { 'segment': 'index' })

@login_required(login_url='login1')
def cadastros(request):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permissions.html')

    return render(request, 'pages/cadastros.html', { 'segment': 'cadastros' })

def billing(request):
    return render(request, 'pages/billing.html', { 'segment': 'billing' })

def tables(request):
    return render(request, 'pages/tables.html', { 'segment': 'tables' })

def vr(request):
    return render(request, 'pages/virtual-reality.html', { 'segment': 'vr' })

def rtl(request):
    return render(request, 'pages/rtl.html', { 'segment': 'rtl' })

def profile(request):
    return render(request, 'pages/profile.html', { 'segment': 'profile' })


# Funções de autenticação

# # Função para verificar se o usuário é administrador
def is_admin(user):
    return user.groups.filter(name='administrador').exists()

# # Função para verificar se o usuário é usuário comum
def is_user(user):
    return user.groups.filter(name='usuario').exists()

# Logout
@login_required(login_url='/accounts/login/')
def logout_view(request):
    logout(request)
    return redirect('/accounts/login/')

@login_required(login_url='login1')
@has_role_decorator('administrador')
def cadastrar_sala(request):
    salas = Sala.objects.all()
    unidades = Unidade.objects.all()

    if request.method == 'POST':
        cor_sala = request.POST.get('cor_sala')
        numero_sala = request.POST.get('numero_sala')
        id_unidade = request.POST.get('id_unidade')

        # Verifique se a unidade existe
        unidade = get_object_or_404(Unidade, id_unidade=id_unidade)

        try:
            # Crie a sala com os dados fornecidos
            Sala.objects.create(
                cor_sala=cor_sala,
                numero_sala=numero_sala,
                id_unidade=unidade  # Use a instância da unidade
            )
            return redirect('cadastrar_salas')  # Redirecionar após a criação
        except Exception as e:
            print(f"Erro ao criar sala: {e}")

    return render(request, 'pages/cadastrar_salas.html', {'salas': salas, 'unidades': unidades})

@login_required(login_url='login1')
def update_sala(request, id_sala):
    sala = get_object_or_404(Sala, id_sala=id_sala)
    unidades = Unidade.objects.all()
    if request.method == 'POST':
        cor_sala = request.POST.get('cor_sala')
        numero_sala = request.POST.get('numero_sala')
        id_unidade = request.POST.get('id_unidade')

        # Verifique se a unidade existe
        unidade = get_object_or_404(Unidade, id_unidade=id_unidade)

        if cor_sala and numero_sala:

            sala.cor_sala = cor_sala
            sala.numero_sala = numero_sala
            sala.id_unidade = unidade

            sala.save()
            return redirect("cadastrar_salas")
        else:
            return render(request, "pages/editar_sala.html", {'sala': sala, 'error': 'Preencha todos os campos.'})

    return render(request, "pages/editar_sala.html", {'sala': sala, 'unidades': unidades})


@login_required(login_url='login1')
def delete_sala(request, id_sala):
    sala= get_object_or_404(Sala, id_sala=id_sala)

    if request.method == 'POST':
        sala.delete()
        return redirect("cadastrar_salas")

    return render(request, "pages/deletar_sala.html", {'sala': sala})

# Gerenciamento de senhas
class UserPasswordResetView(PasswordResetView):
    template_name = 'accounts/password_reset.html'
    form_class = UserPasswordResetForm

class UserPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'accounts/password_reset_confirm.html'
    form_class = UserSetPasswordForm

class UserPasswordChangeView(PasswordChangeView):
    template_name = 'accounts/password_change.html'
    form_class = UserPasswordChangeForm

@login_required(login_url='login1')
@has_role_decorator('administrador')
def users(request):

    users = User.objects.all()
    
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        cargo = request.POST.get('cargo')
        senha = request.POST.get('password')

        user = User.objects.filter(username=username).first()
        if user:
            # return HttpResponse("Já existe um usuário com esse nome")
            return redirect("nome_usuario_erro")


            # Criando um novo usuário
        user = User.objects.create_user(username=username, email=email, password=senha)

            # Associando o usuário ao grupo correspondente
        group, created = Group.objects.get_or_create(name=cargo)
        user.groups.add(group)

            # Salva o usuário
        user.save()

        assign_role(user, cargo)
            
        return redirect('users')

    return render(request, 'pages/page_user.html', {'users': users})

def login(request):
    if request.user.is_authenticated:
        # Se o usuário já estiver autenticado, redirecione para a página inicial
        return redirect('index')

    if request.method == "GET":
        return render(request, 'accounts/login1.html', {'segment': 'login1'})
    else:
        username = request.POST.get('username')
        senha = request.POST.get('senha')
        user = authenticate(username=username, password=senha)
        if user:
            login_django(request, user)
            return redirect('index')
        # return HttpResponse("Usuário ou senha inválidos")
        return redirect("login_erro")

    
@login_required(login_url='login1')
def update_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        cargo = request.POST.get('cargo')
        senha = request.POST.get('password')
        
        if username and email and cargo and senha:
            
            user.username = username
            user.email = email
            user.senha = senha

            user.save()

            assign_role(user, cargo)
            return redirect("users")
        else:
            return render(request, "pages/editar_user.html", {'user': user, 'error': 'Preencha todos os campos.'})

    return render(request, "pages/editar_user.html", {'user': user})

@login_required(login_url='login1')
def delete_user(request, user_id):
    user= get_object_or_404(User, id=user_id)

    if request.method == 'POST':
        user.delete()
        return redirect("users")

    return render(request, "pages/deletar_user.html", {'user': user})


@login_required(login_url='login1')
@has_role_decorator('administrador')
def unis(request):

    unidades = Unidade.objects.all()
    
    if request.method == 'POST':
        nome_unidade = request.POST.get('nome_unidade')
        endereco_unidade = request.POST.get('endereco_unidade')
        CEP_unidade = request.POST.get('CEP_unidade')

        try:
            # Verifique se a unidade já existe
            uni = Unidade.objects.filter(nome_unidade=nome_unidade).first()

            if uni:
                # return HttpResponse("Já existe uma unidade com esse nome")
                return redirect("unis_erro")

            
            print(nome_unidade)
            print(endereco_unidade)
            print(CEP_unidade)

            # Criando uma nova unidade
            uni = Unidade.objects.create(nome_unidade=nome_unidade, endereco_unidade=endereco_unidade, CEP_unidade=CEP_unidade)


            # Salva a unidade
            uni.save()


        except ValueError:
            return render(request, 'pages/page_unidades.html', {
                'error': 'CEP deve ser um número!',
                'unis': Unidade.objects.all()
            })
    
    return render(request, 'pages/page_unidades.html', {'unis': unidades})

@login_required(login_url='login1')
def update_uni(request, unidade_id):
    unidade = get_object_or_404(Unidade, id_unidade=unidade_id)
    if request.method == 'POST':
        nome_unidade = request.POST.get('nome_unidade')
        endereco_unidade = request.POST.get('endereco_unidade')
        CEP_unidade = request.POST.get('CEP_unidade')

        if nome_unidade and endereco_unidade and CEP_unidade:
            unidade.nome_unidade = nome_unidade
            unidade.endereco_unidade = endereco_unidade
            unidade.CEP_unidade = CEP_unidade
            unidade.save()
            
            return redirect("unidade_atendimento")

    return render(request, "pages/editar_unidade.html", {'unidade': unidade})

@login_required(login_url='login1')
def delete_uni(request, unidade_id):
    unidade= get_object_or_404(Unidade, id_unidade=unidade_id)

    if request.method == 'POST':
        unidade.delete()
        return redirect("unidade_atendimento")

    return render(request, "pages/deletar_unidade.html", {'unidade': unidade})

@login_required(login_url='login1')
def logout_user(request):
    # Realiza o logout do usuário  
    logout(request)
    # Redireciona para a página de login após o logout
    return redirect(reverse('login1'))


@login_required(login_url='login1')
def perfil(request):
    user = request.user
    return render(request, 'pages/perfil_usuario.html', {'user': user})

@login_required(login_url='login1')
def update_profile(request, user_id):
    user = get_object_or_404(User, id=user_id)
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        if username and email:
            
            user.username = username
            user.email = email
            if password:
                user.set_password = password

            user.save()

            return redirect("perfil_usuario")
        else:
            return render(request, "pages/editar_perfil.html", {'user': user, 'error': 'Preencha todos os campos.'})

    return render(request, "pages/editar_perfil.html", {'user': user})


@login_required(login_url='login1')
def confirma_consulta(request, psicologo_id):

    psicologo = get_object_or_404(Psicologa, id=psicologo_id)
    pacientes = Paciente.objects.all()
    consultas = ConfirmacaoConsulta.objects.all()

    if request.method == 'POST':
        data = request.POST.get('data')
        paciente = request.POST.get('paciente')
        dia_semana = request.POST.get('dia_semana')
        periodo_atendimento = request.POST.get('periodo_atendimento')
        forma_pagamento = request.POST.get('forma_pagamento')
        horario = request.POST.get('horario')
        valor = request.POST.get('valor')
        confirmacao = request.POST.get('confirmacao')
        observacoes = request.POST.get('observacoes')

        paciente = get_object_or_404(Paciente, id=paciente)


        confirma_consulta = ConfirmacaoConsulta.objects.create(
            dia_semana = dia_semana,
            data = data,
            periodo_atendimento = periodo_atendimento,
            forma_pagamento = forma_pagamento,
            valor = valor,
            confirmacao = confirmacao,
            observacoes = observacoes,
            psicologa = psicologo,
            horario_inicio = horario,
            paciente = paciente
        )

        confirma_consulta.save()

        return redirect('psicologa')

    return render(request, 'pages/confirma_consulta.html', {'pacientes': pacientes, 'psicologo': psicologo, 'consultas': consultas})

@login_required(login_url='login1')
def editar_confirma_consulta(request, id_consulta):

    consulta = get_object_or_404(ConfirmacaoConsulta, id=id_consulta)
    pacientes = Paciente.objects.all()
   
    if request.method == 'POST':

        data = request.POST.get('data')
        paciente = request.POST.get('paciente')
        dia_semana = request.POST.get('dia_semana')
        periodo_atendimento = request.POST.get('periodo_atendimento')
        forma_pagamento = request.POST.get('forma_pagamento')
        horario = request.POST.get('horario')
        valor = request.POST.get('valor')
        confirmacao = request.POST.get('confirmacao')
        observacoes = request.POST.get('observacoes')

        paciente = get_object_or_404(Paciente, id=paciente)

        consulta.data = data
        consulta.paciente = paciente
        consulta.dia_semana = dia_semana
        consulta.periodo_atendimento = periodo_atendimento
        consulta.forma_pagamento = forma_pagamento
        consulta.horario_inicio = horario
        consulta.valor = valor
        consulta.confirmacao = confirmacao
        consulta.observacoes = observacoes

        consulta.save()

        return redirect('psicologa')

    return render(request, 'pages/editar_confirma_consulta.html', {'pacientes': pacientes, 'consulta': consulta})
from django.db.models import Q
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from rolepermissions.decorators import has_role_decorator

@login_required(login_url='login1')
@has_role_decorator('administrador')
def agenda_central(request):
    consultas = Consulta.objects.all()
    psicologas = Psicologa.objects.all()
    salas = Sala.objects.all()
    pacientes = Paciente.objects.all()
    especialidades = Especialidade.objects.all()
    publicos = Publico.objects.all()
    dias_da_semana = ["Segunda", "Terça", "Quarta", "Quinta", "Sexta", "Sábado"]

    if request.method == "POST":
        paciente_id = request.POST.get("paciente_id")
        psicologa_id = request.POST.get('psicologa_id')
        especialidade_id = request.POST.get('especialidade_id')
        publico_id = request.POST.get('publico')
        dia_da_semana = request.POST.get("dia_semana")
        horario = request.POST.get("horario")

        # Filtragem por psicóloga
        if psicologa_id != 'todos':
            psicologo = get_object_or_404(Psicologa, id=psicologa_id)
            consultas = consultas.filter(psicologo=psicologo)

        # Filtragem por paciente
        if paciente_id != 'todos':
            paciente = get_object_or_404(Paciente, id=paciente_id)
            consultas = consultas.filter(Paciente=paciente)

        if especialidade_id and especialidade_id != 'todos':
            psicologas_com_especialidade = Psicologa.objects.filter(
                especialidadepsico__especialidade_id=especialidade_id
            )
            consultas = consultas.filter(psicologo__in=psicologas_com_especialidade)

        # Filtragem por público relacionado às psicólogas
        if publico_id and publico_id != 'todos':
            psicologas_com_publico = Psicologa.objects.filter(
                publicopsico__publico_id=publico_id
            )
            consultas = consultas.filter(psicologo__in=psicologas_com_publico)

        # Filtragem por dia da semana
        if dia_da_semana != "todos" and dia_da_semana in dias_da_semana:
            consultas = consultas.filter(dia_da_semana=dia_da_semana)

        # Filtragem por horário
        if horario and horario != "todos":
            consultas = consultas.filter(horario=horario)

    return render(request, 'pages/page_agenda_central.html', {
        'consultas': consultas,
        'salas': salas,
        'dias_da_semana': dias_da_semana,
        'pacientes': pacientes,
        'psicologas': psicologas,
        'especialidades': especialidades,
        'publicos': publicos,
    })


@login_required(login_url='login1')
def update_consulta(request, consulta_id):
    # Buscar a consulta específica a ser editada
    consulta = get_object_or_404(Consulta, id=consulta_id)
    
    salas_atendimento = Sala.objects.all()
    pacientes = Paciente.objects.all()
    psicologas = Psicologa.objects.all()

    if request.method == 'POST':
        nome_cliente = request.POST.get('nome_cliente')
        nome_psicologo = request.POST.get('nome_psicologo')
        dia_semana = request.POST.get('dia_semana')
        horario_consulta = request.POST.get('horario_consulta')
        sala_atendimento_id = request.POST.get('sala_atendimento')

        sala_atendimento = get_object_or_404(Sala, id_sala=sala_atendimento_id)
        paciente = get_object_or_404(Paciente, id=nome_cliente)
        psicologa = get_object_or_404(Psicologa, id=nome_psicologo)

        # Verificar se outra consulta já existe com os mesmos critérios (dia, horário, sala, paciente e psicólogo)
        consulta_existente = Consulta.objects.filter(
            psicologo=psicologa,
            horario=horario_consulta,
            dia_semana=dia_semana,
            sala=sala_atendimento,
            Paciente=paciente
        ).exclude(id=consulta_id).first()

        if consulta_existente:

            # return HttpResponse("Essa consulta já está cadastrada")
            return redirect("consulta_cadastrada1")

        # Atualizar a consulta com os novos valores
        consulta.psicologo = psicologa
        consulta.horario = horario_consulta
        consulta.sala = sala_atendimento
        consulta.dia_semana = dia_semana
        if paciente.periodo == "Semanal":
            consulta.semanal = paciente.nome
            consulta.quinzenal = ""
        else:
            consulta.quinzenal = paciente.nome
            consulta.semanal = ""
        consulta.Paciente = paciente
        consulta.save()

        return redirect('agenda_central')
    
    return render(request, "pages/edit_consulta.html", {
        'salas': salas_atendimento, 
        'psicologas': psicologas, 
        'pacientes': pacientes, 
        'consulta': consulta
    })


@login_required(login_url='login1')
def delete_consulta(request, id_consulta):
    consulta = get_object_or_404(Consulta, id=id_consulta)

    if request.method == 'POST':
        consulta.delete()
        return redirect('agenda_central')

    return render(request, 'pages/deletar_agenda_central.html', {'consulta': consulta})

@login_required(login_url='login1')
def psicologa(request):
    
    psicologos = Psicologa.objects.all()
    especialidades = Especialidade.objects.all()

    if request.method == 'POST':
        nome = request.POST.get('nome')
        cor = request.POST.get('cor')
        email = request.POST.get('email')
        senha = request.POST.get('senha')
        abordagem = request.POST.get('abordagem')

        psicologa = Psicologa.objects.create(
            nome = nome,
            cor = cor,
            email = email,
            senha = senha,
            abordagem = abordagem
        )

        cargo = 'psicologa'

        user = User.objects.create_user(username=nome, email=email, password=senha)

            # Associando o usuário ao grupo correspondente
        group, created = Group.objects.get_or_create(name=cargo)
        user.groups.add(group)

            # Salva o usuário
        user.save()

        assign_role(user, cargo)

        psicologa.save()
        #usuario.save()

        redirect('psicologa')

    # Obtém o grupo 'psicologa' ou retorna 404 se não existir
    
    # Serializa os dados (ajuste os campos conforme necessário)

    return render(request, 'pages/psicologa.html', {'psicologos': psicologos, 'especialidades': especialidades})


@login_required(login_url='login1')
def visualizar_psicologos(request):

    psicologos = Psicologa.objects.all()

    return render(request, 'pages/visualizacao_psicologas.html', {'psicologos': psicologos })


@login_required(login_url='login1')
def deletar_psicologo(request, psicologo_id):
    # Busca a psicóloga específica pelo ID ou retorna 404 se não for encontrada
    psicologa = get_object_or_404(Psicologa, id=psicologo_id)

    if request.method == 'POST':
        # Exclui a psicóloga
        user = User.objects.filter(username=psicologa.nome).first()
        if user:
            user.delete()  # Exclui também o usuário relacionado, se existir
        
        psicologa.delete()
        
        return redirect('psicologa')  # Redireciona para a lista de psicólogas após a exclusão

    return render(request, 'pages/delete_psicologa.html', {'psicologa': psicologa})

def editar_psicologo(request, psicologo_id):
    psicologo = get_object_or_404(Psicologa, id=psicologo_id)

    # Verificar se o usuário é a psicóloga ou faz parte do grupo 'Administrador'
    if request.user.username != psicologo.nome and not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission1.html')
    

    # Extraindo horas e minutos para o template
    
    if request.method == 'POST':
        nome = request.POST.get('nome')
        cor = request.POST.get('cor')
        

        # Atualiza os campos do psicólogo
        psicologo.nome = nome
        psicologo.cor = cor
        psicologo.save()

        # Redireciona para a página do psicólogo após editar
        return redirect('psicologa')

    return render(request, 'pages/editar_psicologo.html', {
        'psicologo': psicologo
    })

def confirma_consulta(request, psicologo_id):
    psicologo = get_object_or_404(Psicologa, id=psicologo_id)
    pacientes = Paciente.objects.all()
    consulta_confirmadas = ConfirmacaoConsulta.objects.all()

    # Cálculos financeiros
    valor_total_atendimentos = ConfirmacaoConsulta.objects.aggregate(Sum('valor'))['valor__sum'] or 0
    valor_total_cartao = ConfirmacaoConsulta.objects.filter(forma_pagamento='cartao').aggregate(Sum('valor'))['valor__sum'] or 0
    valor_repasse = valor_total_atendimentos / 2
    valor_acerto = valor_repasse - valor_total_cartao

    if request.method == 'POST':
        # Obtendo dados do formulário
        data = request.POST.get('data')
        confirmacao = request.POST.get('confirmacao')
        forma_pagamento = request.POST.get('forma_pagamento')
        valor = request.POST.get('valor')
        observacoes = request.POST.get('observacoes')
        paciente_id = request.POST.get('paciente')
        
        paciente = get_object_or_404(Paciente, id=paciente_id)
        
        # Criação da consulta confirmada
        consulta_confirma = ConfirmacaoConsulta.objects.create(
            data=data,
            psicologo=psicologo,
            confirmacao=confirmacao,
            forma_pagamento=forma_pagamento,
            valor=valor,
            observacoes=observacoes,
            paciente=paciente
        )

        consulta_confirma.save()

        # Redirecionamento após salvar
        return redirect('confirma_consulta', psicologo_id=psicologo_id)

    return render(request, 'pages/confirma_consulta.html', {
        'psicologo': psicologo,
        'pacientes': pacientes,
        'consultas': consulta_confirmadas,
        'valor_total_atendimentos': valor_total_atendimentos,
        'valor_total_cartao': valor_total_cartao,
        'valor_repasse': valor_repasse,
        'valor_acerto': valor_acerto,
    })
@login_required(login_url='login1')
@has_role_decorator('administrador')
def pacientes(request):

    pacientes = Paciente.objects.all()

    if request.method == 'POST':
        nome_paciente = request.POST.get('nome_paciente')
        idade_paciente = request.POST.get('idade_paciente')
        telefone_paciente = request.POST.get('telefone_paciente')
        valor = request.POST.get('valor')
        tipo_atendimento = request.POST.get('tipo_atendimento')
        nome_responsavel = request.POST.get('nome_responsavel')
        periodo_paciente = request.POST.get('periodo_paciente')

        if not nome_responsavel:
            nome_responsavel = ""

        # Validação do valor
        try:
            valor_decimal = Decimal(valor) if valor else Decimal("0")
        except InvalidOperation:
            # Defina um valor padrão ou trate o erro
            valor_decimal = Decimal("0")

        # Criação do paciente
        paciente = Paciente.objects.create(
            nome=nome_paciente,
            idade=idade_paciente,
            valor=valor_decimal,
            tipo_atendimento=tipo_atendimento,
            nome_responsavel=nome_responsavel,
            telefone=telefone_paciente,
            periodo=periodo_paciente
        )

        paciente.save()
        return redirect('pacientes')
    
    return render(request, 'pages/pacientes.html', {'pacientes': pacientes})

@login_required(login_url='login1')
@has_role_decorator('administrador')
def editar_paciente(request, id_paciente):

    paciente = get_object_or_404(Paciente, id=id_paciente)

    if request.method == 'POST':
        nome_paciente = request.POST.get('nome_paciente')
        idade_paciente = request.POST.get('idade_paciente')
        telefone_paciente = request.POST.get('telefone_paciente')
        valor = request.POST.get('valor')
        tipo_atendimento = request.POST.get('tipo_atendimento')
        nome_responsavel = request.POST.get('nome_responsavel')
        periodo_paciente = request.POST.get('periodo_paciente')

        paciente.nome = nome_paciente;
        paciente.valor = valor;
        paciente.idade = idade_paciente;
        paciente.tipo_atendimento = tipo_atendimento;
        paciente.telefone = telefone_paciente;
        paciente.nome_responsavel = nome_responsavel;
        paciente.periodo = periodo_paciente
        
        paciente.save()

        return redirect('pacientes')
    
    return render(request, 'pages/editar_paciente.html', {'paciente': paciente})


@login_required(login_url='login1')
@has_role_decorator('administrador')
def deletar_paciente(request, id_paciente):

    paciente = get_object_or_404(Paciente, id=id_paciente)

    if request.method == 'POST':
        paciente.delete()

        return redirect('pacientes')
    
    return render(request, 'pages/deletar_paciente.html', {'paciente': paciente})



def deletar_consulta(request, psicologo_id, consulta_id):
    consulta = get_object_or_404(ConfirmacaoConsulta, id=consulta_id)
    psicologo = get_object_or_404(Psicologa, id=psicologo_id)
    
    if request.method == "POST":
        consulta.delete()
        return redirect('confirma_consulta', psicologo_id=psicologo_id)
    
    return render(request, 'pages/confirmar_excluir_consulta.html', {
        'psicologo': psicologo,
        'consulta': consulta
    })



def editar_confirma_consulta(request, psicologo_id, consulta_id):
    psicologo = get_object_or_404(Psicologa, id=psicologo_id)
    consulta = get_object_or_404(ConfirmacaoConsulta, id=consulta_id)
    pacientes = Paciente.objects.all()

    if request.method == 'POST':
        # Obtendo os dados do formulário
        consulta.data = request.POST.get('data')
        consulta.confirmacao = request.POST.get('confirmacao')
        consulta.forma_pagamento = request.POST.get('forma_pagamento')
        consulta.valor = request.POST.get('valor')
        consulta.observacoes = request.POST.get('observacoes')
        paciente_id = request.POST.get('paciente')
        consulta.paciente = get_object_or_404(Paciente, id=paciente_id)
        
        # Salvando as alterações
        consulta.save()

        # Redireciona para a página de confirmações de consultas do psicólogo
        return redirect('confirma_consulta', psicologo_id=psicologo_id)
    
    return render(request, 'pages/editar_confirma_consulta.html', {
        'psicologo': psicologo,
        'consulta': consulta,
        'pacientes': pacientes,
    })

#financeiro das psicólogas
@login_required(login_url='login1')
def financeiro(request):
    # psicologas = Psicologa.objects.all()
    financeiros = Financeiro2.objects.all()

    # if request.method == 'POST':
    #     valor_previsto = Decimal(request.POST['valor_previsto'])
    #     valor_pendente = Decimal(request.POST['valor_pendente'])
    #     valor_acertado = Decimal(request.POST['valor_acertado'])
    #     qtd_pacientes = request.POST.get('qtd_pacientes')
    #     valor_total = valor_previsto + valor_pendente + valor_acertado,
    #     desistencias_atendidos = request.POST.get('desistencias_atendidos')
    #     qtd_marcacoes = request.POST.get('qtd_marcacoes')
    #     desistencias_novos = request.POST.get('desistencias_novos')
    #     nome_psicologo = request.POST.get('nome_psicologo')
    #     psicologa = get_object_or_404(Psicologa, nome=nome_psicologo)
    #     # psicologa = get_object_or_404(Psicologa, nome='nome_psicologo')
        
    #     financeiro = Financeiro.objects.create(
    #         psicologa = psicologa,
    #         valor_previsto = valor_previsto,
    #         valor_pendente = valor_pendente,
    #         valor_acertado = valor_acertado,
    #         valor_total = valor_total,
    #         qtd_pacientes = qtd_pacientes,
    #         desistencias_atendidos =  desistencias_atendidos,
    #         qtd_marcacoes = qtd_marcacoes,
    #         desistencias_novos = desistencias_novos
    #     )

    #     financeiro.save()

    #     return redirect('financeiro')
    
    # context = {
    #     'psicologas': psicologas,
    #     'financeiros': financeiros
    # }
    return render(request, 'pages/financeiro.html', {'financeiros':financeiros})


@login_required(login_url='login1') 
def psico_agenda(request, psicologo_id):
    psicologa = get_object_or_404(Psicologa, id=psicologo_id)


    # Verificar se o usuário é a psicóloga ou faz parte do grupo 'Administrador'
    if request.user.username != psicologa.nome and not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission1.html')

    salas_atendimento = Sala.objects.all()
    consultas = Consulta.objects.filter(psicologo=psicologa)
    pacientes = Paciente.objects.all()
    
    if request.method == 'POST':
        nome_cliente = request.POST.get('nome_cliente')
        dia_semana = request.POST.get('dia_semana')
        horario_consulta = request.POST.get('horario_consulta')
        sala_atendimento_id = request.POST.get('sala_atendimento')

        sala_atendimento = get_object_or_404(Sala, id_sala=sala_atendimento_id)
        paciente = get_object_or_404(Paciente, id=nome_cliente)

        # Verificar se uma consulta com esses mesmos critérios já existe
        consulta_existente = Consulta.objects.filter(
            psicologo=psicologa,
            horario=horario_consulta,
            dia_semana=dia_semana,
            sala=sala_atendimento,
            Paciente=paciente
        ).first()

        if consulta_existente:
            # Exibir mensagem de erro
            # return HttpResponse("Essa consulta já está cadastrada")
            return redirect('consulta_cadastrada2')

        # Verificar se já existe uma consulta no mesmo horário e dia com o mesmo psicólogo
        consulta_por_horario = Consulta.objects.filter(
            psicologo=psicologa,
            horario=horario_consulta,
            dia_semana=dia_semana
        ).first()

        if consulta_por_horario:
            # Atualizar a coluna "semanal" ou "quinzenal" dependendo do período do paciente
            if paciente.periodo == "Semanal" and not consulta_por_horario.semanal:
                consulta_por_horario.semanal = paciente.nome
            elif paciente.periodo == "Quinzenal" and not consulta_por_horario.quinzenal:
                consulta_por_horario.quinzenal = paciente.nome
            consulta_por_horario.save()
        else:
            # Criar uma nova consulta se ainda não existe uma com esse horário e psicólogo
            consulta = Consulta.objects.create(
                Paciente=paciente,
                psicologo=psicologa,
                horario=horario_consulta,
                sala=sala_atendimento,
                dia_semana=dia_semana,
                semanal=paciente.nome if paciente.periodo == "Semanal" else "",
                quinzenal=paciente.nome if paciente.periodo == "Quinzenal" else ""
            )
            consulta.save()

        return redirect('psico_agenda', psicologo_id=psicologo_id)
    
    dias_da_semana = ["Segunda", "Terça", "Quarta", "Quinta", "Sexta", "Sábado"]

    return render(request, "pages/psico_agenda.html", {
        'salas': salas_atendimento,  
        'pacientes': pacientes, 
        'agendas': consultas,
        'psicologo': psicologa,
        'dias_da_semana': dias_da_semana
    })

@login_required(login_url='login1')
def cadastrar_especialidade(request):

    especialidades = Especialidade.objects.all()

    if request.method == "POST":
        
        especialidade = request.POST.get('especialidade')

        Especialidade.objects.create(
            especialidade=especialidade
        )

        return redirect('especialidades')
    
    return render(request, 'pages/especialidades.html', 
                  { 'especialidades': especialidades })

@login_required(login_url='login1')
def AssociarPsicoEspecialidade(request, psicologo_id):

    psicologo = get_object_or_404(Psicologa, id=psicologo_id)
    especialidadesGerais = Especialidade.objects.all()

    # Verificar se o usuário é a psicóloga ou faz parte do grupo 'Administrador'
    if request.user.username != psicologo.nome and not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission1.html')


    if request.method == "POST":
        
        especialidade_id = request.POST.get('especialidade_id')
        especialidade = get_object_or_404(Especialidade, id=especialidade_id)

        EspecialidadePsico.objects.create(
            especialidade=especialidade,
            psico=psicologo
        )

        return redirect('psicoEspecialidades', psicologo_id=psicologo.id)

    #Obtendo todos as Especialidades em relação a Psicóloga

    psico_especialidades = EspecialidadePsico.objects.filter(psico=psicologo).select_related(
        'especialidade'
    )

    especiadadesPsico = [pe.especialidade for pe in psico_especialidades]

    return render(request, 'pages/associar_psicologo_especialidade.html', {'especialidadesGerais': especialidadesGerais, 
                                                                           'psicologo': psicologo, 'especiadadesPsico': especiadadesPsico})

@login_required(login_url='login1')
def DissociarPsicoEspecialidade(request, psicologo_id, especialidade_id):

    psicologo = get_object_or_404(Psicologa, id=psicologo_id)

    especialidade = get_object_or_404(Especialidade, id=especialidade_id)

    psico_especialidade = get_object_or_404(EspecialidadePsico, psico=psicologo, especialidade=especialidade)


    if request.method == "POST":

        psico_especialidade.delete()

        return redirect('psicoEspecialidades', psicologo_id=psicologo.id)
    
    return render(request, 'pages/des_psicologo_especialidade.html', {
        'psicologo' : psicologo,
        'especialidade': especialidade
    })

@login_required(login_url='login1')
def AssociarPsicoPublico(request, psicologo_id):

    psicologo = get_object_or_404(Psicologa, id=psicologo_id)
    publicosGerais = Publico.objects.all()

    # Verificar se o usuário é a psicóloga ou faz parte do grupo 'Administrador'
    if request.user.username != psicologo.nome and not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission1.html')

    if request.method == "POST":
        
        publico_id = request.POST.get('publico_id')
        publico = get_object_or_404(Publico, id=publico_id)

        PublicoPsico.objects.create(
            publico=publico,
            psico=psicologo
        )

        return redirect('psicoPublicos', psicologo_id=psicologo.id)

    #Obtendo todos as Especialidades em relação a Psicóloga

    psico_publicos = PublicoPsico.objects.filter(psico=psicologo).select_related(
        'publico'
    )

    publicosPsico = [pp.publico for pp in psico_publicos]

    return render(request, 'pages/associar_psicologo_publico.html', {'publicosGerais': publicosGerais, 
                                                                           'psicologo': psicologo, 'publicosPsico': publicosPsico})

@login_required(login_url='login1')
def DissociarPsicoPublico(request, psicologo_id, publico_id):

    psicologo = get_object_or_404(Psicologa, id=psicologo_id)

    publico = get_object_or_404(Publico, id=publico_id)

    psico_especialidade = get_object_or_404(PublicoPsico, psico=psicologo, publico=publico)


    if request.method == "POST":

        psico_especialidade.delete()

        return redirect('psicoPublicos', psicologo_id=psicologo.id)
    
    return render(request, 'pages/des_psicologo_publico.html', {
        'psicologo' : psicologo,
        'publico': publico
    })

@login_required(login_url='login1')
def cadastrar_publico(request):

    publicos = Publico.objects.all()

    if request.method == "POST":
        
        publico = request.POST.get('publico')

        Publico.objects.create(
            publico=publico
        )

        return redirect('publicos')
    
    return render(request, 'pages/publicos.html', 
                  { 'publicos': publicos })

@login_required(login_url='login1')
def Confirmar_Consulta(request, psicologo_id):

    psicologa = get_object_or_404(Psicologa, id=psicologo_id)
    consultas_psico = Financeiro2.objects.filter(psicologa=psicologa)

    
     # Verificar se o usuário é a psicóloga ou faz parte do grupo 'Administrador'
    if request.user.username != psicologa.nome and not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission1.html')

    if request.method == "POST":
        # Coletar os dados do formulário
        dia_semana = request.POST.get("dia_semana")
        periodo_atendimento = request.POST.get("periodo_atendimento")
        data_inicio = request.POST.get("data_inicio")
        data_fim = request.POST.get("data_fim")
        
        # Filtragem por Dia da Semana (exceto "Todos")
        if dia_semana and dia_semana != "Todos":
            consultas_psico = consultas_psico.filter(dia_semana=dia_semana)
        
        # Filtragem por Período de Atendimento (exceto "Todos")
        if periodo_atendimento and periodo_atendimento != "Todos":
            consultas_psico = consultas_psico.filter(paciente__periodo=periodo_atendimento)
        
        # Filtragem por intervalo de Datas
        if data_inicio and data_fim:
            try:
                data_inicio = datetime.strptime(data_inicio, "%Y-%m-%d")
                data_fim = datetime.strptime(data_fim, "%Y-%m-%d")
                # Filtrar consultas dentro do intervalo de datas
                consultas_psico = consultas_psico.filter(data__range=[data_inicio, data_fim])
            except ValueError:
                # Tratar erro no formato de datas
                messages.error(request, "Por favor, insira datas válidas.")
        elif data_inicio:
            try:
                data_inicio = datetime.strptime(data_inicio, "%Y-%m-%d")
                consultas_psico = consultas_psico.filter(data__gte=data_inicio)
            except ValueError:
                messages.error(request, "Por favor, insira uma data de início válida.")
        elif data_fim:
            try:
                data_fim = datetime.strptime(data_fim, "%Y-%m-%d")
                consultas_psico = consultas_psico.filter(data__lte=data_fim)
            except ValueError:
                messages.error(request, "Por favor, insira uma data de fim válida.")


    # Cálculos financeiros
    valor_total_atendimentos = consultas_psico.filter(presenca='Sim').aggregate(Sum('valor'))['valor__sum'] or 0
    valor_total_cartao = consultas_psico.filter(forma='Cartão').aggregate(Sum('valor'))['valor__sum'] or 0
    valor_repasse = valor_total_atendimentos / 2
    valor_acerto = valor_repasse - valor_total_cartao
    
    return render(request, 'pages/confirma_consulta.html', {'financeiros': consultas_psico
                                                            , 'psicologo': psicologa,
                                                            'valor_total_atendimentos': valor_total_atendimentos,
                                                            'valor_total_cartao': valor_total_cartao,
                                                            'valor_repasse': valor_repasse,
                                                            'valor_acerto': valor_acerto})

@login_required(login_url='login1')
def EditarConfirmaConsulta(request, financeiro_id):

    financeiro = get_object_or_404(Financeiro2, id=financeiro_id)

    if request.method == "POST":

        forma_pagamento = request.POST.get('forma_pagamento')
        presenca = request.POST.get('presenca')
        observacoes = request.POST.get('observacoes')

        financeiro.forma = forma_pagamento
        financeiro.presenca = presenca
        financeiro.observacoes = observacoes

        financeiro.save()

        return redirect('confirma_consulta', psicologo_id=financeiro.psicologa.id)
    
    return render(request, 'pages/editar_confirma_consulta.html', {'financeiro': financeiro})

# Mapeamento de dias da semana para números (0 = Segunda, ..., 5 = Sábado)
DIAS_SEMANA = {
    "Segunda": 0,
    "Terça": 1,
    "Quarta": 2,
    "Quinta": 3,
    "Sexta": 4,
    "Sábado": 5
}

@login_required(login_url='login1')
def AdicionarConfirma_consulta(request, psicologo_id):
    psicologa = get_object_or_404(Psicologa, id=psicologo_id)
    consultas_psico = Consulta.objects.filter(psicologo=psicologa)

    # Data atual
    hoje = datetime.now()

    # Obtém o último domingo antes da data de hoje (considerando o domingo como início da semana anterior)
    ultimo_domingo = hoje - timedelta(days=hoje.weekday() + 1)

    # Calcula o início e o fim da semana anterior (domingo a sábado)
    inicio_semana_passada = ultimo_domingo - timedelta(days=6)
    fim_semana_passada = ultimo_domingo

    if request.method == "POST":
        for consulta in consultas_psico:
            # Obtém o índice do dia da semana
            dia_semana_index = DIAS_SEMANA.get(consulta.dia_semana)

            if dia_semana_index is None:
                continue  # Ignora se o dia da semana não for válido

            # Calcula a data exata da consulta com base no início da semana passada
            data_consulta = inicio_semana_passada + timedelta(days=dia_semana_index)

            # Determina a semana correta dentro do mês
            semana_mes = (data_consulta.day - 1) // 7 + 1  # Calcula a semana no mês (1ª, 2ª, etc.)

            # Verifica se o registro já existe
            existe = Financeiro2.objects.filter(
                dia_semana=consulta.dia_semana,
                horario=consulta.horario,
                psicologa=consulta.psicologo,
                paciente=consulta.Paciente,
                data=data_consulta
            ).exists()

            if not existe:
                Financeiro2.objects.create(
                    dia_semana=consulta.dia_semana,
                    periodo_atendimento=consulta.Paciente.periodo,
                    horario=consulta.horario,
                    psicologa=consulta.psicologo,
                    paciente=consulta.Paciente,
                    valor=consulta.Paciente.valor,
                    data=data_consulta,  # Data ajustada
                    semana=semana_mes  # Semana calculada no mês
                )

        return redirect('confirma_consulta', psicologo_id=psicologa.id)

    return render(request, 'pages/adiciona_confirma_consulta.html', {'psicologo': psicologa})


@login_required(login_url='login1')
def consultar_financeiro(request):
    if request.method == "POST":
        mes = request.POST.get('mes')
        ano = request.POST.get('ano')

        if mes and ano:
            try:
                mes = int(mes)
                ano = int(ano)

                # Calcula o início e o fim do mês selecionado
                data_inicio = datetime(ano, mes, 1)
                if mes == 12:
                    data_fim = datetime(ano + 1, 1, 1) - timedelta(days=1)
                else:
                    data_fim = datetime(ano, mes + 1, 1) - timedelta(days=1)

                # Filtra as consultas financeiras com base no intervalo de datas e exclui as presenças "Não"
                financeiros = Financeiro2.objects.filter(data__range=[data_inicio, data_fim]).exclude(presenca="Nao")

                # Receita bruta por paciente e cálculo dos novos valores
                receita_por_paciente = financeiros.values('paciente__nome').annotate(
                    receita_bruta=Sum('valor'),
                    valor_momento=ExpressionWrapper(Sum('valor') / 2, output_field=DecimalField(max_digits=10, decimal_places=2)),
                    # Uso de Coalesce para tratar valor_pagamento nulo
                    valor_recebido=ExpressionWrapper(Sum(Coalesce(F('valor_pagamento'), 0) / 2), output_field=DecimalField(max_digits=10, decimal_places=2)),
                ).annotate(
                    valor_a_receber=ExpressionWrapper(Sum('valor') / 2 - Sum(Coalesce(F('valor_pagamento'), 0) / 2), output_field=DecimalField(max_digits=10, decimal_places=2))
                ).order_by('paciente__nome')

                # Receita bruta total de todos os pacientes no período
                receita_total = financeiros.aggregate(receita_total=Sum('valor'))

                # Garante que receita_total seja 0 caso não haja consultas financeiras
                valor_total_atendimentos = receita_total['receita_total'] if receita_total['receita_total'] else 0

                # Cálculo do valor momento total de todos os pacientes
                valor_momento_total = valor_total_atendimentos / 2

                # Cálculo dos totais gerais a partir do queryset receita_por_paciente
                total_receita_bruta = sum([paciente['receita_bruta'] for paciente in receita_por_paciente])
                total_valor_momento = sum([paciente['valor_momento'] for paciente in receita_por_paciente])
                total_valor_recebido = sum([paciente['valor_recebido'] for paciente in receita_por_paciente])
                total_valor_a_receber = sum([paciente['valor_a_receber'] for paciente in receita_por_paciente])

                return render(request, 'pages/financeiro.html', {
                    'financeiros': financeiros,
                    'mes': mes,
                    'ano': ano,
                    'receita_por_paciente': receita_por_paciente,
                    'valor_total_atendimentos': valor_total_atendimentos,
                    'valor_momento_total': valor_momento_total,
                    'total_receita_bruta': total_receita_bruta,
                    'total_valor_momento': total_valor_momento,
                    'total_valor_recebido': total_valor_recebido,
                    'total_valor_a_receber': total_valor_a_receber,
                    'message': "Nenhuma consulta financeira encontrada." if not financeiros else None
                })

            except ValueError:
                # Em caso de valores inválidos para mês ou ano
                return render(request, 'pages/consultar_financeiro.html', {
                    'error': "Por favor, insira um mês e ano válidos."
                })

    return render(request, 'pages/consultar_financeiro.html')

@login_required(login_url='login1')
def editar_financeiro(request, id_financeiro):
    financeiro = get_object_or_404(Financeiro2, id=id_financeiro)

    if request.method == "POST":
        valor_pagamento = request.POST.get('valor_pagamento')
        data_pagamento = request.POST.get('data_pagamento')
    
        if valor_pagamento:
            financeiro.valor_pagamento = valor_pagamento
            financeiro.data_pagamento = data_pagamento
            financeiro.save()
            return redirect('editar_financeiro', id_financeiro=id_financeiro)

    return render(request, 'pages/editar_financeiro.html', {'financeiro': financeiro})


@login_required(login_url='login1')
def consulta_cadastrada2(request):
    return render(request, 'pages/consulta_cadastrada2erro.html')


@login_required(login_url='login1')
def consulta_cadastrada1(request):
    return render(request, 'pages/consulta_cadastrada1erro.html')

@login_required(login_url='login1')
def nome_usuario_erro(request):
    return render(request, 'pages/nome_usuario_erro.html')

def login_erro(request):
    return render(request, 'pages/login_erro.html')

@login_required(login_url='login1')
def unis_erro(request):
    return render(request, 'pages/unis_erro.html')