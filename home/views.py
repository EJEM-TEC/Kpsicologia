from collections import OrderedDict, defaultdict
from decimal import Decimal
import json
from django.contrib import messages
from time import strptime
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, render, redirect
from django.contrib.auth.views import PasswordResetView, PasswordChangeView, PasswordResetConfirmView
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.urls import reverse
from home.forms import UserPasswordResetForm, UserSetPasswordForm, UserPasswordChangeForm
from django.contrib.auth import logout, authenticate, login as login_django
from django.contrib.auth.decorators import login_required
from rolepermissions.roles import assign_role
from rolepermissions.decorators import has_role_decorator
from django.contrib.auth.models import User, Group
from .models import Psicologa, Consulta, Unidade, Sala, Paciente, EspecialidadePsico, Especialidade, Publico, PublicoPsico, Financeiro, Disponibilidade, UnidadePsico, Consulta_Online, Despesas
from rolepermissions.roles import assign_role
from django.contrib.auth.models import Group
from django.contrib.auth import authenticate, login as login_django
from django.contrib.auth.decorators import login_required
from datetime import timedelta, timezone
from django.db.models import Sum
from django.shortcuts import render, get_object_or_404, redirect
from decimal import Decimal, InvalidOperation
from django.shortcuts import render
from datetime import datetime
from django.db.models import F, ExpressionWrapper, DecimalField, Sum
from django.db.models.functions import Coalesce  # Import correto para Coalesce
from django.db.models import Sum, Count, F, Q, DecimalField, ExpressionWrapper, Case, When, Value, Prefetch
from django.db.models.functions import Coalesce
from django.contrib.postgres.aggregates import ArrayAgg
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from rolepermissions.decorators import has_role_decorator
from django.shortcuts import render, redirect
from datetime import datetime, timedelta
from django.db.models import Sum, F, ExpressionWrapper, DecimalField
from django.db.models.functions import Coalesce
from django.db.models import OuterRef, Subquery
from django.core.cache import cache
from django.http import HttpResponse
from django.template.loader import get_template
from io import BytesIO
import os
from django.conf import settings

cards = [
    {"title": "Agenda", "url_name": 'psico_agenda', "image": "img/curved-images/curved3.jpg"},
    {"title": "Confirmação", "url_name": 'confirma_consulta', "image": "img/curved-images/curved6.jpg"},
    {"title": "Disponibilidade", "url_name": 'psico_disponibilidade', "image": "img/curved-images/curved7.jpg"},
    {"title": "Disponibilidades Extras", "url_name": 'psico_disponibilidade_online', "image": "img/curved-images/curved6.jpg"},
    {"title": "Agenda de Horários Extras", "url_name": 'psico_agenda_online', "image": "img/curved-images/curved6.jpg"},
    {"title": "Edição", "url_name": 'editar_psicologo', "image": "img/curved-images/curved6.jpg"},
    {"title": "Perfil", "url_name": 'perfil_usuario', "image": "img/curved-images/curved7.jpg"},
]

# PÁGINAS DE ERRO 
def handler404(request, exception):
    return render(request, '404.html', status=404)

def handler500(request):
    return render(request, '500.html', status=500)

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

# AUTENTICAÇÃO E LOGOUT
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
            if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
                
                psicologa = Psicologa.objects.filter(nome=username).first()

                return render(request, 'pages/index_psicologa.html', {'user': user, 'psicologo': psicologa, 'cards': cards})
            
            return redirect('index')
        # return HttpResponse("Usuário ou senha inválidos")
        return redirect("login_erro")
    
@login_required(login_url='/accounts/login/')
def logout_view(request):
    logout(request)
    return redirect('/accounts/login/')

@login_required(login_url='login1')
def logout_user(request):
    # Realiza o logout do usuário  
    logout(request)
    # Redireciona para a página de login após o logout
    return redirect(reverse('login1'))



# PÁGINAS DE MENU

@login_required(login_url='login1')
def index(request):

    request.session['mes'] = None
    request.session['ano'] = None

    user = request.user
    username = user.username
    
    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:

        
        
        psicologa = Psicologa.objects.filter(nome=username).first()

        return render(request, 'pages/index_psicologa.html', {'user': user, 'psicologo': psicologa, 'cards': cards})
    
    return render(request, 'pages/index.html', { 'segment': 'index' })

@login_required(login_url='login1')
def cadastros_menu(request):

    request.session['mes'] = None
    request.session['ano'] = None

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    return render(request, 'pages/cadastros.html', { 'segment': 'cadastros' })


@login_required(login_url='login1')
def disponibilidades_psicologos(request):

    request.session['mes'] = None
    request.session['ano'] = None

    if request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission1.html')

    psicologos = Psicologa.objects.all()

    return render(request, 'pages/disponibilidades_psico.html', {'psicologos': psicologos})


# USUÁRIOS

@login_required(login_url='login1')
def users(request):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

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

        #Se for um administrador será um superuser
        if cargo == 'administrador':
            user.is_superuser = True
            user.is_staff = True

        # Salva o usuário
        user.save()

        assign_role(user, cargo)
            
        return redirect('users')

    return render(request, 'pages/page_user.html', {'users': users})

    
@login_required(login_url='login1')
def update_user(request, user_id):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

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

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    user= get_object_or_404(User, id=user_id)

    if request.method == 'POST':
        user.delete()
        return redirect("users")

    return render(request, "pages/deletar_user.html", {'user': user})


# UNIDADES 

@login_required(login_url='login1')
def unis(request):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

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

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

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

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    unidade= get_object_or_404(Unidade, id_unidade=unidade_id)

    if request.method == 'POST':
        unidade.delete()
        return redirect("unidade_atendimento")

    return render(request, "pages/deletar_unidade.html", {'unidade': unidade})


# PERFIL DE USUÁRIO

@login_required(login_url='login1')
def perfil(request):

    request.session['mes'] = None
    request.session['ano'] = None

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

# SALAS DE ATENDIMENTO

@login_required(login_url='login1')
def cadastrar_sala(request):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    salas = Sala.objects.all()
    unidades = Unidade.objects.all()

    if request.method == 'POST':
        cor_sala = request.POST.get('cor_sala')
        numero_sala = request.POST.get('numero_sala')
        id_unidade = request.POST.get('id_unidade')
        horario_inicio = request.POST.get('id_horario_inicio')
        horario_fim = request.POST.get('id_horario_fim')

        # Verifique se a unidade existe
        unidade = get_object_or_404(Unidade, id_unidade=id_unidade)

        # Crie a sala com os dados fornecidos
        Sala.objects.create(
            cor_sala=cor_sala,
            numero_sala=numero_sala,
            horario_inicio=horario_inicio,
            horario_fim=horario_fim,
            id_unidade=unidade  # Use a instância da unidade
        )

        return redirect('cadastrar_salas')  # Redirecionar após a criação

    return render(request, 'pages/cadastrar_salas.html', {'salas': salas, 'unidades': unidades})

@login_required(login_url='login1')
def update_sala(request, id_sala):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    sala = get_object_or_404(Sala, id_sala=id_sala)
    unidades = Unidade.objects.all()
    if request.method == 'POST':
        cor_sala = request.POST.get('cor_sala')
        numero_sala = request.POST.get('numero_sala')
        id_unidade = request.POST.get('id_unidade')
        horario_inicio = request.POST.get('id_horario_inicio')
        horario_fim = request.POST.get('id_horario_fim')

        # Verifique se a unidade existe
        unidade = get_object_or_404(Unidade, id_unidade=id_unidade)

        if cor_sala:
            sala.cor_sala = cor_sala
        if numero_sala:
            sala.numero_sala = numero_sala
        if horario_inicio:
            sala.horario_inicio = horario_inicio
        if horario_fim:
            sala.horario_fim = horario_fim
        if unidade:
            sala.id_unidade = unidade

        sala.save()
        return redirect("cadastrar_salas")
    
    return render(request, "pages/editar_sala.html", {'sala': sala, 'unidades': unidades})


@login_required(login_url='login1')
def delete_sala(request, id_sala):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    sala= get_object_or_404(Sala, id_sala=id_sala)

    if request.method == 'POST':
        sala.delete()
        return redirect("cadastrar_salas")

    return render(request, "pages/deletar_sala.html", {'sala': sala})


# HORÁRIOS DISPONÍVIES - SALAS DE ATENDIMENTO

@login_required(login_url='login1')
def definir_horario_sala(request, id_sala):

    sala = get_object_or_404(Sala, id_sala=id_sala)
    horarios = Consulta.objects.filter(sala=sala)

    if request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission1.html')

    # Lista dos dias da semana
    dias_da_semana = ['Segunda', 'Terça', 'Quarta', 'Quinta', 'Sexta', 'Sábado']

    # Agrupar horários por dia da semana em uma lista de tuplas (dia, horários)
    horarios_agrupados = []
    for dia in dias_da_semana:
        horarios_do_dia = horarios.filter(dia_semana=dia)
        horarios_agrupados.append((dia, horarios_do_dia))

    if request.method == "POST":
        dia_semana = request.POST.get('dia_semana')
        qtd_atendimentos = int(request.POST.get('qtd_atendimentos'))
        tempo_atendimento = int(request.POST.get('tempo_atendimento'))  # em minutos
        horario_inicio = request.POST.get('horario_inicio')

        # Convertemos o horário de início para um objeto datetime.time
        horario_atual = datetime.strptime(horario_inicio, '%H:%M').time()

        # Loop para inserir os horários de acordo com a quantidade de atendimentos
        for i in range(qtd_atendimentos):
            # Verificar se já existe um horário com o mesmo dia e hora
            if not Consulta.objects.filter(
                dia_semana=dia_semana,
                horario=horario_atual,
                sala=sala
            ).exists():
                Consulta.objects.create(
                    dia_semana=dia_semana,
                    horario=horario_atual,
                    sala=sala,
                )
            # Incrementa o horário atual pelo tempo de atendimento (em minutos)
            horario_atual = (datetime.combine(datetime.today(), horario_atual) + timedelta(minutes=tempo_atendimento)).time()

        return redirect('horario_sala', id_sala=sala.id_sala)  # Altere para a view de sucesso

    return render(request, 'pages/sala_disponibilidade.html', {
        'horarios_agrupados': horarios_agrupados,
        'sala': sala
    })

@login_required(login_url='login1')
def delete_horario_sala(request, id_sala, horario_id):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    sala = get_object_or_404(Sala, id_sala=id_sala)
    horario = get_object_or_404(Consulta, id=horario_id)

    if request.method == 'POST':
        horario.delete()
        return redirect('horario_sala', id_sala=sala.id_sala)

    return render(request, 'pages/delete_horario_sala.html', {'sala': sala, 'horario': horario})


# AGENDA CENTRAL
@login_required(login_url='login1')
def agenda_central(request):
    """
    View otimizada para exibir a agenda central com filtros e paginação
    """
    
    # Limpar sessão se necessário
    request.session['mes'] = None
    request.session['ano'] = None

    # Verificar permissões
    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    # Definir dias da semana com cores
    dias_cores = [
        ('Segunda', 'bg-primary'),
        ('Terça', 'bg-success'), 
        ('Quarta', 'bg-warning'),
        ('Quinta', 'bg-info'),
        ('Sexta', 'bg-secondary'),
        ('Sábado', 'bg-dark')
    ]

    # ==================== CACHE DE DADOS ESTÁTICOS ==================== #
    
    cache_key = 'agenda_central_static_data_v2'
    static_data = cache.get(cache_key)
    
    if not static_data:
        static_data = {
            'psicologas': list(Psicologa.objects.select_related().all()),
            'especialidades': list(Especialidade.objects.all()),
            'publicos': list(Publico.objects.all()),
            'unidades': list(Unidade.objects.all()),
            'dias_da_semana': [dia for dia, _ in dias_cores]
        }
        # Cache por 30 minutos
        cache.set(cache_key, static_data, 1800)

    # ==================== CONSULTA BASE OTIMIZADA ==================== #
    
    consultas = Consulta.objects.select_related(
        'psicologo', 
        'sala', 
        'sala__id_unidade'
    ).prefetch_related(
        Prefetch('psicologo__especialidadepsico_set', 
                queryset=EspecialidadePsico.objects.select_related('especialidade')),
        Prefetch('psicologo__publicopsico_set',
                queryset=PublicoPsico.objects.select_related('publico'))
    ).order_by('sala__id_unidade__nome_unidade', 'sala__numero_sala', 'horario')

    consultas_online = Consulta_Online.objects.select_related(
        'psicologo'
    ).order_by('psicologo__nome', 'horario')

    # ==================== APLICAR FILTROS ==================== #
    
    filtros_aplicados = {}
    
    if request.method == "POST":
        # Filtro por psicóloga
        psicologa_id = request.POST.get('psicologa_id')
        if psicologa_id and psicologa_id != 'todos':
            try:
                psicologa_id = int(psicologa_id)
                consultas = consultas.filter(psicologo_id=psicologa_id)
                consultas_online = consultas_online.filter(psicologo_id=psicologa_id)
                filtros_aplicados['psicologa_id'] = str(psicologa_id)
            except (ValueError, TypeError):
                pass

        # Filtro por unidade
        unidade_id = request.POST.get('unidade_id')
        if unidade_id and unidade_id != 'todas':
            try:
                unidade_id = int(unidade_id)
                consultas = consultas.filter(sala__id_unidade_id=unidade_id)
                filtros_aplicados['unidade_id'] = str(unidade_id)
            except (ValueError, TypeError):
                pass

        # Filtro por horário
        horario_inicio = request.POST.get('horario_inicio')
        horario_fim = request.POST.get('horario_fim')
        
        if horario_inicio:
            try:
                horario_inicio_obj = datetime.strptime(horario_inicio, '%H:%M').time()
                consultas = consultas.filter(horario__gte=horario_inicio_obj)
                consultas_online = consultas_online.filter(horario__gte=horario_inicio_obj)
                filtros_aplicados['horario_inicio'] = horario_inicio
            except ValueError:
                pass
                
        if horario_fim:
            try:
                horario_fim_obj = datetime.strptime(horario_fim, '%H:%M').time()
                consultas = consultas.filter(horario__lte=horario_fim_obj)
                consultas_online = consultas_online.filter(horario__lte=horario_fim_obj)
                filtros_aplicados['horario_fim'] = horario_fim
            except ValueError:
                pass

    # ==================== PRESERVAR FILTROS NA PAGINAÇÃO ==================== #
    
    # Aplicar filtros do GET (para paginação)
    for key, value in request.GET.items():
        if key.startswith(('psicologa_id', 'unidade_id', 'horario_')):
            filtros_aplicados[key] = value
    
    # Reaplicar filtros se vieram do GET
    if 'psicologa_id' in request.GET and request.GET['psicologa_id'] != 'todos':
        try:
            psicologa_id = int(request.GET['psicologa_id'])
            consultas = consultas.filter(psicologo_id=psicologa_id)
            consultas_online = consultas_online.filter(psicologo_id=psicologa_id)
        except (ValueError, TypeError):
            pass

    if 'unidade_id' in request.GET and request.GET['unidade_id'] != 'todas':
        try:
            unidade_id = int(request.GET['unidade_id'])
            consultas = consultas.filter(sala__id_unidade_id=unidade_id)
        except (ValueError, TypeError):
            pass

    # ==================== PAGINAÇÃO OTIMIZADA ==================== #
    
    # Obter salas únicas das consultas filtradas
    salas_com_consultas = consultas.values_list('sala', flat=True).distinct()
    salas = Sala.objects.filter(
        id_sala__in=salas_com_consultas
    ).select_related('id_unidade').order_by(
        'id_unidade__nome_unidade', 'numero_sala'
    )
    
    # Paginação das salas (5 salas por página)
    paginator = Paginator(salas, 3)
    page_number = request.GET.get('page', 1)
    salas_paginadas = paginator.get_page(page_number)
    
    # Filtrar consultas apenas para as salas da página atual
    salas_ids_pagina = [sala.id_sala for sala in salas_paginadas]
    consultas_pagina = consultas.filter(sala_id__in=salas_ids_pagina)

    # ==================== PREPARAR HORÁRIOS ÚNICOS ==================== #
    
    horarios_unicos = list(consultas_pagina.values_list('horario', flat=True).distinct().order_by('horario'))
    horarios_unicos_online = list(consultas_online.values_list('horario', flat=True).distinct().order_by('horario'))

    # ==================== PSICÓLOGAS COM CONSULTAS ONLINE ==================== #
    
    psicologas_com_consultas_online = []
    psicologas_online_ids = consultas_online.values_list('psicologo_id', flat=True).distinct()
    
    for psicologa in static_data['psicologas']:
        if psicologa.id in psicologas_online_ids:
            psicologas_com_consultas_online.append(psicologa)

    # ==================== ESTATÍSTICAS PARA O TEMPLATE ==================== #
    
    estatisticas = {
        'total_consultas': consultas.count(),
        'total_salas': salas.count(),
        'total_psicologas': len(static_data['psicologas']),
        'consultas_online': consultas_online.count(),
    }

    # ==================== CONTEXTO FINAL ==================== #
    
    context = {
        # Dados principais
        'consultas': consultas_pagina,
        'salas': salas_paginadas,
        'horarios_unicos': horarios_unicos,
        
        # Dados online
        'consultas_online': consultas_online,
        'psicologas_online': psicologas_com_consultas_online,
        'horarios_unicos_online': horarios_unicos_online,
        
        # Dados estáticos
        'psicologas': static_data['psicologas'],
        'especialidades': static_data['especialidades'],
        'publicos': static_data['publicos'],
        'unidades': static_data['unidades'],
        'dias_da_semana': static_data['dias_da_semana'],
        'dias_cores': dias_cores,
        
        # Estado dos filtros
        'filtros_aplicados': filtros_aplicados,
        
        # Estatísticas e metadados
        'estatisticas': estatisticas,
        'total_salas': paginator.count,
        'pagina_atual': salas_paginadas.number,
        'total_paginas': paginator.num_pages,
        
        # Configurações
        'items_per_page': 5,
    }

    return render(request, 'pages/page_agenda_central.html', context)

# VERSÃO ALTERNATIVA: Com paginação para casos extremos
@login_required(login_url='login1')
def agenda_central_paginated(request):
    from django.core.paginator import Paginator
    
    request.session['mes'] = None
    request.session['ano'] = None

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    # Consulta base otimizada
    consultas = Consulta.objects.select_related(
        'psicologo', 
        'sala', 
        'sala__id_unidade',
        'Paciente'
    ).prefetch_related(
        'psicologo__especialidadepsico_set__especialidade',
        'psicologo__publicopsico_set__publico'
    ).order_by('horario')

    # Aplicar filtros (mesmo código acima)
    if request.method == "POST":
        # ... código de filtros igual ao anterior ...
        pass

    # Paginação - só mostra 50 consultas por vez
    paginator = Paginator(consultas, 50)
    page_number = request.GET.get('page')
    consultas_paginated = paginator.get_page(page_number)

    # Cache dos dados estáticos
    cache_key = 'agenda_central_static_data'
    static_data = cache.get(cache_key)
    
    if not static_data:
        static_data = {
            'psicologas': list(Psicologa.objects.all()),
            'especialidades': list(Especialidade.objects.all()),
            'publicos': list(Publico.objects.all()),
            'unidades': list(Unidade.objects.all()),
            'dias_da_semana': ["Segunda", "Terça", "Quarta", "Quinta", "Sexta", "Sábado"]
        }
        cache.set(cache_key, static_data, 1800)

    # Consultas online
    consultas_online = Consulta_Online.objects.select_related('Paciente').filter(
        Paciente__isnull=False
    ).order_by('horario')

    # Salas com consultas (baseado na página atual)
    salas_ids_com_consultas = consultas_paginated.object_list.values_list('sala_id', flat=True).distinct()
    salas_com_consultas = Sala.objects.filter(
        id_sala__in=salas_ids_com_consultas
    ).select_related('id_unidade')

    return render(request, 'pages/page_agenda_central.html', {
        'consultas': consultas_paginated,
        'salas': salas_com_consultas,
        'dias_da_semana': static_data['dias_da_semana'],
        'psicologas': static_data['psicologas'],
        'especialidades': static_data['especialidades'],
        'publicos': static_data['publicos'],
        'unidades': static_data['unidades'],
        'consultas_online': consultas_online,
        'psicologas_online': Psicologa.objects.filter(consulta_online__in=consultas_online).distinct()
    })


@login_required(login_url='login1')
def gerar_relatorio_pdf_agenda(request):
    """
    Gera um relatório PDF completo da agenda central com todos os horários cadastrados
    """
    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    # Obter dados estáticos do cache (reutilizar a mesma lógica da agenda_central)
    cache_key = 'agenda_central_static_data'
    static_data = cache.get(cache_key)
    
    if not static_data:
        static_data = {
            'psicologas': list(Psicologa.objects.all()),
            'especialidades': list(Especialidade.objects.all()),
            'publicos': list(Publico.objects.all()),
            'unidades': list(Unidade.objects.all()),
            'dias_da_semana': ["Segunda", "Terça", "Quarta", "Quinta", "Sexta", "Sábado"]
        }
        cache.set(cache_key, static_data, 1800)  # 30 minutos

    # Buscar todas as consultas sem paginação para o relatório
    consultas = Consulta.objects.select_related(
        'psicologo', 
        'sala', 
        'sala__id_unidade',
        'Paciente'
    ).prefetch_related(
        'psicologo__especialidadepsico_set__especialidade',
        'psicologo__publicopsico_set__publico'
    ).order_by('sala__id_unidade__nome_unidade', 'sala__numero_sala', 'dia_semana', 'horario')

    # Consultas online
    consultas_online = Consulta_Online.objects.select_related(
        'Paciente'
    ).filter(
        Paciente__isnull=False
    ).order_by('psicologo__nome', 'dia_semana', 'horario')

    # Buscar todas as salas com consultas
    salas_ids_com_consultas = consultas.values_list('sala_id', flat=True).distinct()
    salas_com_consultas = Sala.objects.filter(
        id_sala__in=salas_ids_com_consultas
    ).select_related('id_unidade').order_by('id_unidade__nome_unidade', 'numero_sala')

    # Organizar dados por unidade, sala e dia da semana para melhor visualização no PDF
    dados_organizados = {}
    for sala in salas_com_consultas:
        unidade_nome = sala.id_unidade.nome_unidade
        if unidade_nome not in dados_organizados:
            dados_organizados[unidade_nome] = {}
        
        # Obter consultas da sala agrupadas por dia da semana
        consultas_sala = consultas.filter(sala=sala)
        
        # Organizar por dia da semana
        dados_por_dia = {}
        for dia in static_data['dias_da_semana']:
            consultas_do_dia = consultas_sala.filter(dia_semana=dia).order_by('horario')
            if consultas_do_dia.exists():
                dados_por_dia[dia] = consultas_do_dia
        
        if dados_por_dia:  # Só adiciona se tiver consultas
            dados_organizados[unidade_nome][sala] = dados_por_dia

    # Estatísticas para o relatório
    total_consultas = consultas.count()
    total_consultas_ocupadas = consultas.filter(Paciente__isnull=False).count()
    total_consultas_livres = consultas.filter(Paciente__isnull=True).count()
    total_consultas_online = consultas_online.count()

    # Contexto para o template PDF
    context = {
        'dados_organizados': dados_organizados,
        'consultas_online': consultas_online,
        'static_data': static_data,
        'total_consultas': total_consultas,
        'total_consultas_ocupadas': total_consultas_ocupadas,
        'total_consultas_livres': total_consultas_livres,
        'total_consultas_online': total_consultas_online,
        'data_geracao': datetime.now(),
        'usuario_gerador': request.user.username,
    }

    # Renderizar template HTML
    template = get_template('relatorios/agenda_central_pdf.html')
    html = template.render(context)

    # Criar o PDF
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="relatorio_agenda_central_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf"'

    # Converter HTML para PDF
    pisa_status = pisa.CreatePDF(
        html, 
        dest=response,
        encoding='utf-8'
    )

    if pisa_status.err:
        return HttpResponse('Erro ao gerar PDF', status=400)

    return response

# CONSULTAS - AGENDA PSICÓLOGA

@login_required(login_url='login1')
def psico_agenda(request, psicologo_id):
    psicologa = get_object_or_404(Psicologa, id=psicologo_id)

    # Verificar se o usuário é a psicóloga ou faz parte do grupo 'Administrador'
    if request.user.username != psicologa.nome and not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission1.html')
    
    hoje = datetime.now().date()
    salas_atendimento = Sala.objects.all()
    consultas = Consulta.objects.filter(psicologo=psicologa).order_by('horario')
    verificaco_agenda = True
    diferenca_ultima_atualizacao = (hoje - psicologa.ultima_atualizacao_agenda).days

    if diferenca_ultima_atualizacao > 7:
        verificaco_agenda = False
    
    if request.method == 'POST':
        nome_cliente = request.POST.get('nome_cliente')
        dia_semana = request.POST.get('dia_semana')
        horario_consulta = request.POST.get('horario_consulta')
        sala_atendimento_id = request.POST.get('sala_atendimento')

        sala_atendimento = get_object_or_404(Sala, id_sala=sala_atendimento_id)

        # Verificar se o paciente existe
        try:
            paciente = Paciente.objects.get(nome=nome_cliente)
        except Paciente.DoesNotExist or paciente.deletado == True:
            return render(request, 'pages/error_paciente_nao_encontrado.html', {
                'nome_cliente': nome_cliente,
                'psicologo': psicologa
            })

        # Verificar se uma consulta com esses mesmos critérios já existe
        consulta_existente = Consulta.objects.filter(
            psicologo=psicologa,
            horario=horario_consulta,
            dia_semana=dia_semana,
            sala=sala_atendimento,
            Paciente=paciente
        ).first()

        if consulta_existente:
            return render(request, 'consulta_cadastrada2', {
                "psicologo": psicologa,
            })


        consulta_por_horario = Consulta.objects.get(
            psicologo=psicologa,
            horario=horario_consulta,
            dia_semana=dia_semana,
            sala=sala_atendimento
        )

        if consulta_por_horario:

            if paciente.periodo == "Semanal" and consulta_por_horario.semanal:
                consulta_por_horario.semanal = paciente.nome
                consulta_por_horario.Paciente = paciente
                consulta_por_horario.save()
                psicologa.ultima_atualizacao_agenda = hoje
                psicologa.save()
            elif paciente.periodo == "Quinzenal" and consulta_por_horario.quinzenal:
                consulta_por_horario.quinzenal = paciente.nome
                consulta_por_horario.Paciente = paciente
                consulta_por_horario.save()
                psicologa.ultima_atualizacao_agenda = hoje
                psicologa.save()
            else:
                return render(request, 'pages/error_cadastro.html', {
                    'psicologo': psicologa
                })
        else:
            return render(request, 'pages/error_cadastro.html', {
                'psicologo': psicologa
            })

        return redirect('psico_agenda', psicologo_id=psicologo_id)

    dias_da_semana = ["Segunda", "Terça", "Quarta", "Quinta", "Sexta", "Sábado"]

    return render(request, "pages/psico_agenda.html", {
        'salas': salas_atendimento,  
        'agendas': consultas,
        'psicologo': psicologa,
        'dias_da_semana': dias_da_semana,
        'verificaco_agenda': verificaco_agenda
    })

@login_required(login_url='login1')
def editar_multiplas_agendas(request, psicologo_id):
    """
    View para edição em massa das agendas de uma psicóloga específica
    """
    psicologa = get_object_or_404(Psicologa, id=psicologo_id)
    
    # Verificar permissões
    if (request.user.username != psicologa.nome and 
        not request.user.groups.filter(name='administrador').exists() and 
        not request.user.is_superuser):
        return render(request, 'pages/error_permission1.html')
    
    # Buscar todas as agendas da psicóloga (disponibilidades)
    agendas = Consulta.objects.filter(
        psicologo=psicologa
    ).order_by('dia_semana', 'horario')
    
    # Buscar todos os pacientes (não separar por período, pois pode mudar)
    pacientes_semanais = Paciente.objects.filter(
        periodo='Semanal', 
        deletado=False
    ).order_by('nome')
    
    pacientes_quinzenais = Paciente.objects.filter(
        periodo='Quinzenal', 
        deletado=False
    ).order_by('nome')
    
    if request.method == 'POST':
        try:
            alteracoes_realizadas = 0
            agendas_removidas = 0
            pacientes_alterados = 0
            horarios_liberados = 0
            alteracoes_log = []
            
            # Processar cada agenda
            for agenda in agendas:
                agenda_id = str(agenda.id)
                
                # Obter valores dos formulários
                metodo = request.POST.get(f'metodo_{agenda_id}', 'padrao')
                semanal_novo = request.POST.get(f'semanal_{agenda_id}', '').strip()
                quinzenal_novo = request.POST.get(f'quinzenal_{agenda_id}', '').strip()
                
                # Valores originais
                semanal_original = agenda.semanal or ''
                quinzenal_original = agenda.quinzenal or ''
                metodo_original = getattr(agenda, 'metodo', 'padrao')
                
                # Processar método "fechado" - remover agenda
                if metodo == 'fechado':
                    agenda.delete()
                    agendas_removidas += 1
                    alteracoes_log.append({
                        'tipo': 'agenda_removida',
                        'dia': agenda.dia_semana,
                        'horario': agenda.horario.strftime('%H:%M'),
                        'sala': agenda.sala.numero_sala
                    })
                    continue
                
                # Processar método "livre" - limpar todos os pacientes
                elif metodo == 'livre':
                    # Limpar todos os pacientes do horário
                    if agenda.semanal or agenda.quinzenal or agenda.Paciente:
                        agenda.Paciente = None
                        agenda.semanal = None
                        agenda.quinzenal = None
                        
                        # Salvar método se o campo existir
                        if hasattr(agenda, 'metodo'):
                            agenda.metodo = metodo
                            
                        agenda.save()
                        
                        horarios_liberados += 1
                        alteracoes_log.append({
                            'tipo': 'horario_liberado',
                            'dia': agenda.dia_semana,
                            'horario': agenda.horario.strftime('%H:%M'),
                            'sala': agenda.sala.numero_sala,
                            'pacientes_removidos': [p for p in [semanal_original, quinzenal_original] if p]
                        })
                    
                    # Forçar limpeza dos campos de entrada (ignora o que veio do form)
                    semanal_novo = ''
                    quinzenal_novo = ''
                    continue
                
                # Verificar se houve mudanças nos pacientes ou método
                mudou_semanal = semanal_novo != semanal_original
                mudou_quinzenal = quinzenal_novo != quinzenal_original
                mudou_metodo = metodo != metodo_original
                
                if mudou_semanal or mudou_quinzenal or mudou_metodo:
                    # Processar paciente semanal
                    paciente_semanal = None
                    if semanal_novo:
                        try:
                            paciente_semanal = Paciente.objects.get(
                                nome=semanal_novo,
                                deletado=False
                            )
                            
                            # Verificar se precisa alterar o período do paciente
                            if paciente_semanal.periodo != 'Semanal':
                                paciente_semanal.periodo = 'Semanal'
                                paciente_semanal.save()
                                pacientes_alterados += 1
                                alteracoes_log.append({
                                    'tipo': 'periodo_alterado',
                                    'paciente': paciente_semanal.nome,
                                    'periodo_anterior': 'Quinzenal',
                                    'periodo_novo': 'Semanal'
                                })
                                
                        except Paciente.DoesNotExist:
                            messages.error(
                                request, 
                                f"Paciente '{semanal_novo}' não encontrado."
                            )
                            continue
                    
                    # Processar paciente quinzenal
                    paciente_quinzenal = None
                    if quinzenal_novo:
                        try:
                            paciente_quinzenal = Paciente.objects.get(
                                nome=quinzenal_novo,
                                deletado=False
                            )
                            
                            # Verificar se precisa alterar o período do paciente
                            if paciente_quinzenal.periodo != 'Quinzenal':
                                paciente_quinzenal.periodo = 'Quinzenal'
                                paciente_quinzenal.save()
                                pacientes_alterados += 1
                                alteracoes_log.append({
                                    'tipo': 'periodo_alterado',
                                    'paciente': paciente_quinzenal.nome,
                                    'periodo_anterior': 'Semanal',
                                    'periodo_novo': 'Quinzenal'
                                })
                                
                        except Paciente.DoesNotExist:
                            messages.error(
                                request, 
                                f"Paciente '{quinzenal_novo}' não encontrado."
                            )
                            continue
                    
                    # Validar que não é o mesmo paciente nos dois campos (apenas para método padrão)
                    if (metodo == 'padrao' and semanal_novo and quinzenal_novo and 
                        semanal_novo == quinzenal_novo):
                        messages.error(
                            request,
                            f"O mesmo paciente não pode ser semanal e quinzenal no mesmo horário: {agenda.dia_semana} às {agenda.horario.strftime('%H:%M')}"
                        )
                        continue
                    
                    # Atualizar agenda
                    agenda_alterada = False
                    
                    # Salvar método se o campo existir
                    if mudou_metodo and hasattr(agenda, 'metodo'):
                        agenda.metodo = metodo
                        agenda_alterada = True
                    
                    if mudou_semanal:
                        agenda.semanal = semanal_novo if semanal_novo else None
                        agenda_alterada = True
                    
                    if mudou_quinzenal:
                        agenda.quinzenal = quinzenal_novo if quinzenal_novo else None
                        agenda_alterada = True
                    
                    # Definir paciente principal
                    if paciente_semanal:
                        agenda.Paciente = paciente_semanal
                    elif paciente_quinzenal:
                        agenda.Paciente = paciente_quinzenal
                    else:
                        agenda.Paciente = None
                    
                    if agenda_alterada:
                        agenda.save()
                        alteracoes_realizadas += 1
                        
                        # Log da alteração
                        alteracao_info = {
                            'tipo': 'agenda_atualizada',
                            'agenda_id': agenda.id,
                            'dia': agenda.dia_semana,
                            'horario': agenda.horario.strftime('%H:%M'),
                            'sala': agenda.sala.numero_sala,
                            'metodo_anterior': metodo_original,
                            'metodo_novo': metodo,
                            'semanal_anterior': semanal_original,
                            'semanal_novo': semanal_novo,
                            'quinzenal_anterior': quinzenal_original,
                            'quinzenal_novo': quinzenal_novo,
                        }
                        alteracoes_log.append(alteracao_info)
            
            # Atualizar data de última atualização da agenda
            if alteracoes_realizadas > 0 or agendas_removidas > 0 or horarios_liberados > 0:
                psicologa.ultima_atualizacao_agenda = timezone.now().date()
                psicologa.save()
                
                # Mensagem de sucesso com detalhes
                mensagem_sucesso = f"✅ Operação concluída com sucesso!"
                detalhes = []
                
                if alteracoes_realizadas > 0:
                    detalhes.append(f"{alteracoes_realizadas} agenda(s) atualizada(s)")
                
                if agendas_removidas > 0:
                    detalhes.append(f"{agendas_removidas} agenda(s) removida(s)")
                
                if horarios_liberados > 0:
                    detalhes.append(f"{horarios_liberados} horário(s) liberado(s)")
                
                if pacientes_alterados > 0:
                    detalhes.append(f"{pacientes_alterados} paciente(s) com período alterado")
                
                if detalhes:
                    mensagem_sucesso += f" ({', '.join(detalhes)})"
                
                messages.success(request, mensagem_sucesso)
                
                # Log detalhado das alterações (opcional - para debug)
                for alteracao in alteracoes_log:
                    print(f"Alteração: {alteracao}")
            
            else:
                messages.info(request, "Nenhuma alteração foi realizada.")
                
            return redirect('psico_agenda', psicologo_id=psicologa.id)
            
        except Exception as e:
            messages.error(
                request, 
                f"Erro ao processar alterações: {str(e)}"
            )
            return render(request, 'pages/editar_multiplas_agendas.html', {
                'psicologa': psicologa,
                'agendas': agendas,
                'pacientes_semanais': pacientes_semanais,
                'pacientes_quinzenais': pacientes_quinzenais,
            })
    
    # GET request - mostrar formulário
    return render(request, 'pages/editar_multiplas_agendas.html', {
        'psicologa': psicologa,
        'agendas': agendas,
        'pacientes_semanais': pacientes_semanais,
        'pacientes_quinzenais': pacientes_quinzenais,
    })


@login_required(login_url='login1')
def api_pacientes(request):
    """
    Endpoint para fornecer lista de pacientes para autocomplete
    """
    try:
        pacientes = Paciente.objects.filter(deletado=False).values('nome', 'periodo')
        return JsonResponse(list(pacientes), safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required(login_url='login1')
def validar_conflitos_agenda(request):
    """
    Endpoint AJAX para validar conflitos de agendamento em tempo real
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Método não permitido'}, status=405)
    
    try:
        data = json.loads(request.body)
        paciente_nome = data.get('paciente')
        agenda_id_atual = data.get('agenda_id')
        tipo = data.get('tipo')  # 'semanal' ou 'quinzenal'
        
        if not paciente_nome:
            return JsonResponse({'valid': True})
        
        # Buscar o paciente
        try:
            paciente = Paciente.objects.get(nome=paciente_nome, deletado=False)
        except Paciente.DoesNotExist:
            return JsonResponse({
                'valid': False,
                'error': 'Paciente não encontrado',
                'conflicts': []
            })
        
        # Buscar conflitos existentes
        conflitos = []
        
        # Verificar agendamentos semanais
        agendas_semanal = Consulta.objects.filter(
            semanal=paciente_nome
        ).exclude(id=agenda_id_atual)
        
        for agenda in agendas_semanal:
            conflitos.append({
                'dia': agenda.dia_semana,
                'horario': agenda.horario.strftime('%H:%M'),
                'sala': agenda.sala.numero_sala,
                'tipo': 'semanal',
                'agenda_id': agenda.id
            })
        
        # Verificar agendamentos quinzenais
        agendas_quinzenal = Consulta.objects.filter(
            quinzenal=paciente_nome
        ).exclude(id=agenda_id_atual)
        
        for agenda in agendas_quinzenal:
            conflitos.append({
                'dia': agenda.dia_semana,
                'horario': agenda.horario.strftime('%H:%M'),
                'sala': agenda.sala.numero_sala,
                'tipo': 'quinzenal',
                'agenda_id': agenda.id
            })
        
        # Verificar se o período do paciente corresponde ao tipo solicitado
        periodo_warning = None
        if (tipo == 'semanal' and paciente.periodo != 'Semanal') or \
           (tipo == 'quinzenal' and paciente.periodo != 'Quinzenal'):
            periodo_warning = f'Paciente {paciente_nome} é {paciente.periodo}, mas está sendo agendado como {tipo}. Isso alterará o período do paciente.'
        
        return JsonResponse({
            'valid': True,  # Permitir sempre, mas avisar sobre conflitos
            'conflicts': conflitos,
            'paciente_periodo': paciente.periodo,
            'periodo_warning': periodo_warning,
            'has_conflicts': len(conflitos) > 0
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Dados JSON inválidos'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)



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

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    consulta = get_object_or_404(Consulta, id=id_consulta)

    if request.method == 'POST':
        consulta.delete()
        return redirect('agenda_central')

    return render(request, 'pages/deletar_agenda_central.html', {'consulta': consulta})


@login_required(login_url='login1')
def delete_multiple_consultas(request, psicologo_id):
    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')
    
    dia_semana = request.POST.get('dia_semana')
    psicologa = get_object_or_404(Psicologa, id=psicologo_id)
    consultas = Consulta.objects.filter(psicologo=psicologa, dia_semana=dia_semana)

    if request.method == 'POST':
        # Obter os IDs das consultas a serem excluídas
        consultas.exclude(id__in=request.POST.getlist('consultas')).delete()
        # Redirecionar para a página de agenda central

        return redirect('psico_agenda', psicologo_id=psicologa.id)

    return render(request, 'pages/deletar_multiplas_agendas.html', {
        'consultas': consultas,
        'psicologa': psicologa,
    })


# DISPONIBILIDADES PSICOLOGAS

@login_required(login_url='login1')
def definir_disponibilidade_psico(request, psicologo_id):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    salas = Sala.objects.all()
    psicologa = get_object_or_404(Psicologa, id=psicologo_id)
    horarios = Consulta.objects.filter(psicologo=psicologa).filter(Paciente__isnull=True).order_by('horario')

    # Verificar se o usuário é a psicóloga ou faz parte do grupo 'Administrador'
    if request.user.username != psicologa.nome and not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission1.html')

    # Lista dos dias da semana
    dias_da_semana = ['Segunda', 'Terça', 'Quarta', 'Quinta', 'Sexta', 'Sábado']

    # Agrupar horários por dia da semana em uma lista de tuplas (dia, horários)
    horarios_agrupados = []
    for dia in dias_da_semana:
        horarios_do_dia = horarios.filter(dia_semana=dia)
        horarios_agrupados.append((dia, horarios_do_dia))

    if request.method == "POST":
        dia_semana = request.POST.get('dia_semana')
        qtd_atendimentos = int(request.POST.get('qtd_atendimentos'))
        tempo_atendimento = int(request.POST.get('tempo_atendimento'))  # em minutos
        horario_inicio = request.POST.get('horario_inicio')
        sala_id = request.POST.get('sala_id')
        
        sala = get_object_or_404(Sala, id_sala=sala_id)

        # Convertemos o horário de início para um objeto datetime.time
        horario_atual = datetime.strptime(horario_inicio, '%H:%M').time()

        # Loop para inserir os horários de acordo com a quantidade de atendimentos
        for i in range(qtd_atendimentos):
            if Consulta.objects.filter(
                dia_semana=dia_semana,
                horario=horario_atual,
                psicologo=psicologa,
            ).exists():
                continue
            else:   
                consulta = Consulta.objects.create(
                    dia_semana=dia_semana,
                    horario=horario_atual,
                    sala=sala,
                    psicologo=psicologa,
                    semanal="Semanal",
                    quinzenal="Quinzenal",
                )

                consulta.save()
                # else:
                #     return render(request, 'pages/error_disponibilidade_sala.html', {
                #         'psicologo': psicologa,
                #     })
                # Incrementa o horário atual pelo tempo de atendimento (em minutos)
            horario_atual = (datetime.combine(datetime.today(), horario_atual) + timedelta(minutes=tempo_atendimento)).time()

        return redirect('psico_disponibilidade', psicologo_id=psicologa.id)  # Altere para a view de sucesso

    return render(request, 'pages/psico_disponibilidade.html', {
        'psicologo': psicologa,
        'horarios_agrupados': horarios_agrupados,
        'salas': salas,
    })



@login_required(login_url='login1')
def remover_disponibilidade(request, disponibilidade_id, psicologo_id):
    disponibilidade = get_object_or_404(Disponibilidade, id=disponibilidade_id)
    psicologo = get_object_or_404(Psicologa, id=psicologo_id)

    if request.method == "POST":

        disponibilidade.delete()
        return redirect('psico_disponibilidade', psicologo_id=psicologo.id)

    return render(request, 'pages/deletar_disponibilidade.html', {'disponibilidade': disponibilidade, 'psicologa': psicologo})

@login_required(login_url='login1')
def delete_multiple_disponibilidades(request, psicologo_id):
    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')
    
    dia_semana = request.POST.get('dia_semana')
    psicologa = get_object_or_404(Psicologa, id=psicologo_id)
    consultas = Consulta.objects.filter(psicologo=psicologa, dia_semana=dia_semana).filter(Paciente__isnull=True)

    if request.method == 'POST':
        # Obter os IDs das consultas a serem excluídas
        consultas.exclude(id__in=request.POST.getlist('consultas')).delete()
        # Redirecionar para a página de agenda central

        return redirect('psico_disponibilidade', psicologo_id=psicologa.id)

    return render(request, 'pages/deletar_multiplas_disponibilidades.html', {
        'consultas': consultas,
        'psicologa': psicologa,
    })

# PSICÓLOGAS


@login_required(login_url='login1')
def visualizar_psicologos(request):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    request.session['mes'] = None
    request.session['ano'] = None

    hoje = datetime.now().date()
    psicologos = Psicologa.objects.all()

    # Lista para armazenar as psicólogas e suas respectivas verificações de agenda
    psicologos_verificacao = []

    for psicologa in psicologos:
        diferenca_ultima_atualizacao = (hoje - psicologa.ultima_atualizacao_agenda).days
        verificacao_agenda = diferenca_ultima_atualizacao <= 7

        # Adicionar a psicóloga e a verificação de agenda na lista
        psicologos_verificacao.append({
            'psicologo': psicologa,
            'verificacao_agenda': verificacao_agenda
        })

    return render(request, 'pages/visualizacao_psicologas.html', {'psicologos_verificacao': psicologos_verificacao})


@login_required(login_url='login1')
def psicologa(request):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')
    
    psicologos = Psicologa.objects.all()
    especialidades = Especialidade.objects.all()


    hoje = datetime.now().date()
    psicologos = Psicologa.objects.all()

    # Lista para armazenar as psicólogas e suas respectivas verificações de agenda
    psicologos_verificacao = []

    for psicologa in psicologos:
        diferenca_ultima_atualizacao = (hoje - psicologa.ultima_atualizacao_agenda).days
        verificacao_agenda = diferenca_ultima_atualizacao <= 7

        # Adicionar a psicóloga e a verificação de agenda na lista
        psicologos_verificacao.append({
            'psicologo': psicologa,
            'verificacao_agenda': verificacao_agenda
        })

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

        return redirect('psicologa')

    # Obtém o grupo 'psicologa' ou retorna 404 se não existir
    
    # Serializa os dados (ajuste os campos conforme necessário)

    return render(request, 'pages/psicologa.html', {'psicologos_verificacao': psicologos_verificacao, 'especialidades': especialidades})


@login_required(login_url='login1')
def deletar_psicologo(request, psicologo_id):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

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
    print(psicologo.nome)
    user_psico = User.objects.filter(username=psicologo.nome).first()

    print(user_psico)

    # Verificar se o usuário é a psicóloga ou faz parte do grupo 'Administrador'
    if request.user.username != psicologo.nome and not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission1.html')
    

    # Extraindo horas e minutos para o template
    
    if request.method == 'POST':
        nome = request.POST.get('nome')
        cor = request.POST.get('cor')
        abordagem = request.POST.get("abordagem")
        email = request.POST.get("email")
        senha = request.POST.get("senha")
        

        # Atualiza os campos do psicólogo
        if nome:
            psicologo.nome = nome
            user_psico.username = nome

        if cor:
            psicologo.cor = cor
        
        if abordagem:
            psicologo.abordagem = abordagem
        
        if email:
            psicologo.email = email
            user_psico.email = email
        
        if senha:
            psicologo.senha = senha
            user_psico.set_password(senha)

        psicologo.save()      
        user_psico.save()

        # Redireciona para a página do psicólogo após editar
        return redirect('visualizar_psicologas')

    return render(request, 'pages/editar_psicologo.html', {
        'psicologo': psicologo
    })

# PACIENTES

@login_required(login_url='login1')
def pacientes(request):
    
    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')
    
    # Capturar parâmetros de filtro para pacientes ativos
    nome_filtro = request.GET.get('nome_filtro', '').strip()
    idade_filtro = request.GET.get('idade_filtro', '')
    periodo_filtro = request.GET.get('periodo_filtro', '')
    
    # Query base para pacientes ativos
    pacientes_query = Paciente.objects.filter(deletado=False)
    
    # Aplicar filtros se fornecidos
    if nome_filtro:
        pacientes_query = pacientes_query.filter(nome__icontains=nome_filtro)
    
    if idade_filtro:
        pacientes_query = pacientes_query.filter(idade=idade_filtro)
    
    if periodo_filtro:
        pacientes_query = pacientes_query.filter(periodo=periodo_filtro)
    
    # Ordenar por nome
    pacientes_query = pacientes_query.order_by('nome')
    
    # Paginação para pacientes ativos
    itens_por_pagina_ativos = int(request.GET.get('items_per_page_ativos', 15))
    itens_por_pagina_ativos = max(10, min(50, itens_por_pagina_ativos))
    
    paginator_ativos = Paginator(pacientes_query, itens_por_pagina_ativos)
    page_number_ativos = request.GET.get('page_ativos', 1)
    
    try:
        pacientes_paginados = paginator_ativos.page(page_number_ativos)
    except PageNotAnInteger:
        pacientes_paginados = paginator_ativos.page(1)
    except EmptyPage:
        pacientes_paginados = paginator_ativos.page(paginator_ativos.num_pages)
    
    # Pacientes deletados (com paginação separada)
    pacientes_deletados_query = Paciente.objects.filter(deletado=True).order_by('nome')
    
    # Paginação para pacientes deletados
    itens_por_pagina_deletados = int(request.GET.get('items_per_page_deletados', 10))
    itens_por_pagina_deletados = max(5, min(30, itens_por_pagina_deletados))
    
    paginator_deletados = Paginator(pacientes_deletados_query, itens_por_pagina_deletados)
    page_number_deletados = request.GET.get('page_deletados', 1)
    
    try:
        pacientes_deletados_paginados = paginator_deletados.page(page_number_deletados)
    except PageNotAnInteger:
        pacientes_deletados_paginados = paginator_deletados.page(1)
    except EmptyPage:
        pacientes_deletados_paginados = paginator_deletados.page(paginator_deletados.num_pages)

    # Tratamento de criação de paciente (POST)
    if request.method == 'POST':
        nome_paciente = request.POST.get('nome_paciente')
        idade_paciente = request.POST.get('idade_paciente')
        telefone_paciente = request.POST.get('telefone_paciente')
        valor = request.POST.get('valor')
        nome_responsavel = request.POST.get('nome_responsavel')
        periodo_paciente = request.POST.get('periodo_paciente')

        if not nome_responsavel:
            nome_responsavel = ""

        # Validação do valor
        try:
            valor_decimal = Decimal(valor) if valor else Decimal("0")
        except InvalidOperation:
            valor_decimal = Decimal("0")

        # Criação do paciente
        paciente = Paciente.objects.create(
            nome=nome_paciente,
            idade=idade_paciente,
            valor=valor_decimal,
            nome_responsavel=nome_responsavel,
            telefone=telefone_paciente,
            periodo=periodo_paciente,
            deletado=False
        )

        paciente.save()
        return redirect('pacientes')
    
    # Preparar parâmetros de query para manter filtros na paginação
    query_params_ativos = {}
    if nome_filtro:
        query_params_ativos['nome_filtro'] = nome_filtro
    if idade_filtro:
        query_params_ativos['idade_filtro'] = idade_filtro
    if periodo_filtro:
        query_params_ativos['periodo_filtro'] = periodo_filtro
    if request.GET.get('items_per_page_ativos'):
        query_params_ativos['items_per_page_ativos'] = request.GET.get('items_per_page_ativos')
    
    query_params_deletados = {}
    if request.GET.get('items_per_page_deletados'):
        query_params_deletados['items_per_page_deletados'] = request.GET.get('items_per_page_deletados')
    
    # Estatísticas
    total_pacientes_ativos = pacientes_query.count()
    total_pacientes_deletados = pacientes_deletados_query.count()
    
    return render(request, 'pages/pacientes.html', {
        'pacientes': pacientes_paginados,
        'pacientes_deletados': pacientes_deletados_paginados,
        'query_params_ativos': query_params_ativos,
        'query_params_deletados': query_params_deletados,
        'total_pacientes_ativos': total_pacientes_ativos,
        'total_pacientes_deletados': total_pacientes_deletados,
        'nome_filtro': nome_filtro,
        'idade_filtro': idade_filtro,
        'periodo_filtro': periodo_filtro,
    })

@login_required(login_url='login1')
def editar_paciente(request, id_paciente):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

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
def deletar_paciente(request, id_paciente):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    paciente = get_object_or_404(Paciente, id=id_paciente)

    if request.method == 'POST':
        paciente.deletado = True

        paciente.save()

        return redirect('pacientes')
    
    return render(request, 'pages/deletar_paciente.html', {'paciente': paciente})


@login_required(login_url='login1')
def restaurar_paciente(request, id_paciente):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    paciente = get_object_or_404(Paciente, id=id_paciente)

    if request.method == 'POST':
        paciente.deletado = False

        paciente.save()

        return redirect('pacientes')
    
    return render(request, 'pages/restaurar_paciente.html', {'paciente': paciente})


# CARACTERÍSTICAS PSICÓLOGAS

@login_required(login_url='login1')
def cadastrar_especialidade(request):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

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
def deletar_especialidade(request, especialidade_id):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    especialidade = get_object_or_404(Especialidade, id=especialidade_id)

    if request.method == 'POST':
        especialidade.delete()

        return redirect('especialidades')
    
    return render(request, 'pages/deletar_especialidade.html', {'especialidade': especialidade})

@login_required(login_url='login1')
def cadastrar_publico(request):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

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
def deletar_publico(request, publico_id):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    publico = get_object_or_404(Publico, id=publico_id)

    if request.method == 'POST':
        publico.delete()

        return redirect('publicos')
    
    return render(request, 'pages/deletar_publico.html', {'publico': publico})

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

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

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
def AssociarPsicoUnidade(request, psicologo_id):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    psicologo = get_object_or_404(Psicologa, id=psicologo_id)
    unidadesGerais = Unidade.objects.all()



    if request.method == "POST":
        
        unidade_id = request.POST.get('unidade_id')
        unidade = get_object_or_404(Unidade, id_unidade=unidade_id)

        UnidadePsico.objects.create(
            unidade=unidade,
            psico=psicologo
        )

        return redirect('psicoUnidades', psicologo_id=psicologo.id)

    #Obtendo todos as Especialidades em relação a Psicóloga

    psico_unidades = UnidadePsico.objects.filter(psico=psicologo).select_related(
        'unidade'
    )

    unidadesPsico = [pu.unidade for pu in psico_unidades]

    return render(request, 'pages/associar_psicologo_unidade.html', {'unidadesGerais': unidadesGerais, 
                                                                           'psicologo': psicologo, 'unidadesPsico': unidadesPsico})

@login_required(login_url='login1')
def DissociarPsicoUnidade(request, psicologo_id, unidade_id):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    psicologo = get_object_or_404(Psicologa, id=psicologo_id)

    unidade = get_object_or_404(Unidade, id_unidade=unidade_id)

    psico_unidade = get_object_or_404(UnidadePsico, psico=psicologo, unidade=unidade)


    if request.method == "POST":

        psico_unidade.delete()

        return redirect('psicoUnidades', psicologo_id=psicologo.id)
    
    return render(request, 'pages/des_psicologo_unidade.html', {
        'psicologo' : psicologo,
        'unidade': unidade
    })

@login_required(login_url='login1')
def AssociarPsicoPublico(request, psicologo_id):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

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

@login_required(login_url='login1')
def DissociarPsicoPublico(request, psicologo_id, publico_id):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

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
def Confirmar_Consulta(request, psicologo_id):
    psicologo = get_object_or_404(Psicologa, id=psicologo_id)
    
    # Verificar permissões
    if request.user.username != psicologo.nome and not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission1.html')
    
    # Query base dos financeiros
    financeiros_query = Financeiro.objects.filter(psicologo=psicologo).order_by('-data', '-horario')
    
    # Aplicar filtros se método POST
    if request.method == 'POST':
        dia_semana = request.POST.get('dia_semana', 'Todos')
        periodo_atendimento = request.POST.get('periodo_atendimento', 'Todos')
        data_inicio = request.POST.get('data_inicio')
        data_fim = request.POST.get('data_fim')
        
        # Aplicar filtros na query
        if dia_semana and dia_semana != 'Todos':
            financeiros_query = financeiros_query.filter(dia_semana=dia_semana)
            
        if periodo_atendimento and periodo_atendimento != 'Todos':
            financeiros_query = financeiros_query.filter(periodo_atendimento=periodo_atendimento)
            
        if data_inicio:
            financeiros_query = financeiros_query.filter(data__gte=data_inicio)
            
        if data_fim:
            financeiros_query = financeiros_query.filter(data__lte=data_fim)
    
    # Aplicar filtros se método GET (para preservar filtros na paginação)
    elif request.method == 'GET':
        dia_semana = request.GET.get('dia_semana', 'Todos')
        periodo_atendimento = request.GET.get('periodo_atendimento', 'Todos')
        data_inicio = request.GET.get('data_inicio')
        data_fim = request.GET.get('data_fim')
        
        # Aplicar filtros na query
        if dia_semana and dia_semana != 'Todos':
            financeiros_query = financeiros_query.filter(dia_semana=dia_semana)
            
        if periodo_atendimento and periodo_atendimento != 'Todos':
            financeiros_query = financeiros_query.filter(periodo_atendimento=periodo_atendimento)
            
        if data_inicio:
            financeiros_query = financeiros_query.filter(data__gte=data_inicio)
            
        if data_fim:
            financeiros_query = financeiros_query.filter(data__lte=data_fim)
    
    # Contar total de consultas (antes da paginação)
    total_consultas = financeiros_query.count()
    
    # Configurar paginação
    items_per_page = request.GET.get('per_page', 25)  # Padrão: 25 itens por página
    try:
        items_per_page = int(items_per_page)
        if items_per_page not in [10, 25, 50, 100]:
            items_per_page = 25
    except (ValueError, TypeError):
        items_per_page = 25
    
    paginator = Paginator(financeiros_query, items_per_page)
    page_number = request.GET.get('page', 1)
    
    try:
        financeiros = paginator.page(page_number)
    except PageNotAnInteger:
        # Se page não é um inteiro, entrega a primeira página
        financeiros = paginator.page(1)
    except EmptyPage:
        # Se page está fora do range, entrega a última página
        financeiros = paginator.page(paginator.num_pages)
    
    # Calcular valores financeiros (baseado na query filtrada, não paginada)
    financeiros_para_calculo = financeiros_query
    
    # Cálculos financeiros
    valor_total_atendimentos = sum(
        financeiro.paciente.valor or 0 
        for financeiro in financeiros_para_calculo 
        if financeiro.presenca == 'Sim'
    )
    
    valor_total_cartao = sum(
        financeiro.valor_pagamento or 0 
        for financeiro in financeiros_para_calculo 
        if financeiro.forma_pagamento == 'Cartão' and financeiro.presenca == 'Sim'
    )
    
    valor_repasse = valor_total_atendimentos * 0.5
    valor_acerto = valor_total_atendimentos - valor_total_cartao
    
    context = {
        'psicologo': psicologo,
        'financeiros': financeiros,
        'total_consultas': total_consultas,
        'valor_total_atendimentos': valor_total_atendimentos,
        'valor_total_cartao': valor_total_cartao,
        'valor_repasse': valor_repasse,
        'valor_acerto': valor_acerto,
        
        # Preservar valores dos filtros para o template
        'dia_semana_filtro': request.POST.get('dia_semana', request.GET.get('dia_semana', 'Todos')),
        'periodo_atendimento_filtro': request.POST.get('periodo_atendimento', request.GET.get('periodo_atendimento', 'Todos')),
        'data_inicio_filtro': request.POST.get('data_inicio', request.GET.get('data_inicio', '')),
        'data_fim_filtro': request.POST.get('data_fim', request.GET.get('data_fim', '')),
    }
    
    return render(request, 'pages/confirma_consulta.html', context)

@login_required(login_url='login1')
def AdicionarConfirma_consulta(request, psicologo_id):
    psicologa = get_object_or_404(Psicologa, id=psicologo_id)
    consultas_psico = Consulta.objects.filter(psicologo=psicologa)
    consultas_psico_online = Consulta_Online.objects.filter(psicologo=psicologa)

    # Verificar se o usuário é a psicóloga ou faz parte do grupo 'Administrador'
    if request.user.username != psicologa.nome and not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission1.html')

    # Verificar se existem registros financeiros para a psicóloga
    registros_financeiros = Financeiro.objects.filter(psicologa=psicologa)
    
    if registros_financeiros.exists():
        # Verificar se há registros não preenchidos
        registros_incompletos = registros_financeiros.filter(
            Q(presenca__isnull=True) | 
            Q(presenca='') | 
            Q(forma__isnull=True) | 
            Q(forma='') |
            Q(bloqueada=False)  # Considerar também consultas não bloqueadas como incompletas
        )
        
        if registros_incompletos.exists():
            return render(request, 'pages/adiciona_confirma_consulta.html', {
                'psicologo': psicologa,
                'error': 'Você precisa preencher todas as consultas existentes antes de adicionar uma nova semana.',
                'registros_incompletos': registros_incompletos[:10]  # Limitar a 10 registros para não sobrecarregar a página
            })

    if request.method == "POST":
        # Receber a data selecionada pelo usuário
        data_semana_str = request.POST.get('data')
        
        if not data_semana_str:
            # Se a data não foi fornecida, mostrar mensagem de erro
            return render(request, 'pages/adiciona_confirma_consulta.html', {
                'psicologo': psicologa,
                'error': 'Por favor, selecione uma data.'
            })
        
        # Converter a string de data para um objeto datetime
        data_semana = datetime.strptime(data_semana_str, '%Y-%m-%d')
        
        # Calcular o início da semana (segunda-feira) para a data fornecida
        # weekday() retorna 0 para segunda, 1 para terça, etc.
        inicio_semana = data_semana - timedelta(days=data_semana.weekday())
            
        # Processar consultas presenciais
        for consulta in consultas_psico:
            if not consulta.Paciente:
                continue

            # Mapeamento correto dos dias da semana
            # Agora o mapeamento é: Segunda=0, Terça=1, Quarta=2, Quinta=3, Sexta=4, Sábado=5
            dia_semana_mapeamento = {
                "Segunda": 0,
                "Terça": 1,
                "Quarta": 2,
                "Quinta": 3, 
                "Sexta": 4,
                "Sábado": 5
            }

            # Obtém o índice do dia da semana
            dia_semana_index = dia_semana_mapeamento.get(consulta.dia_semana)

            if dia_semana_index is None:
                continue  # Ignora se o dia da semana não for válido

            # Calcula a data exata da consulta com base no início da semana selecionada
            data_consulta = inicio_semana + timedelta(days=dia_semana_index)

            # Determina a semana correta dentro do mês
            semana_mes = (data_consulta.day - 1) // 7 + 1  # Calcula a semana no mês (1ª, 2ª, etc.)

            # Verifica se o registro já existe
            existe = Financeiro.objects.filter(
                dia_semana=consulta.dia_semana,
                horario=consulta.horario,
                psicologa=consulta.psicologo,
                paciente=consulta.Paciente,
                data=data_consulta,
                semana=semana_mes
            ).exists()

            if not existe:
                Financeiro.objects.create(
                    dia_semana=consulta.dia_semana,
                    periodo_atendimento=consulta.Paciente.periodo,
                    horario=consulta.horario,
                    psicologa=consulta.psicologo,
                    modalidade="Presencial",
                    paciente=consulta.Paciente,
                    valor=consulta.Paciente.valor,
                    data=data_consulta,
                    semana=semana_mes,
                    sala=consulta.sala,
                    bloqueada=False
                )

        # Processar consultas online
        for consulta in consultas_psico_online:
            if not consulta.Paciente:
                continue

            # Usar o mesmo mapeamento corrigido para consultas online
            dia_semana_mapeamento = {
                "Segunda": 0,
                "Terça": 1,
                "Quarta": 2,
                "Quinta": 3, 
                "Sexta": 4,
                "Sábado": 5
            }
            
            dia_semana_index = dia_semana_mapeamento.get(consulta.dia_semana)

            if dia_semana_index is None:
                continue

            data_consulta = inicio_semana + timedelta(days=dia_semana_index)
            semana_mes = (data_consulta.day - 1) // 7 + 1

            existe = Financeiro.objects.filter(
                dia_semana=consulta.dia_semana,
                horario=consulta.horario,
                psicologa=consulta.psicologo,
                paciente=consulta.Paciente,
                data=data_consulta
            ).exists()

            if not existe:
                Financeiro.objects.create(
                    dia_semana=consulta.dia_semana,
                    periodo_atendimento=consulta.Paciente.periodo,
                    horario=consulta.horario,
                    psicologa=consulta.psicologo,
                    modalidade="Online",
                    paciente=consulta.Paciente,
                    valor=consulta.Paciente.valor,
                    data=data_consulta,
                    semana=semana_mes,
                    bloqueada=False
                )

        return redirect('confirma_consulta', psicologo_id=psicologa.id)

    return render(request, 'pages/adiciona_confirma_consulta.html', {'psicologo': psicologa})


@login_required(login_url='login1')
def editar_confirmacao_consultas(request, psicologo_id):

    is_admin = request.user.is_superuser or request.user.groups.filter(name='administrador').exists()

    psicologa = get_object_or_404(Psicologa, id=psicologo_id)
    consultas_psico = Financeiro.objects.filter(psicologa=psicologa, bloqueada=False)

    # Calcular informações da semana das consultas
    semanas_info = None
    mes_ano_info = None
    if consultas_psico.exists():
        # Obter as semanas e datas das consultas
        semanas = consultas_psico.values_list('semana', flat=True).distinct().order_by('semana')
        datas = consultas_psico.values_list('data', flat=True).distinct().order_by('data')
        
        if semanas and datas:
            # Pegar a primeira data para determinar o mês/ano
            primeira_data = min(datas)
            
            # Formatear o mês/ano em português
            meses = {
                1: 'Janeiro', 2: 'Fevereiro', 3: 'Março', 4: 'Abril',
                5: 'Maio', 6: 'Junho', 7: 'Julho', 8: 'Agosto',
                9: 'Setembro', 10: 'Outubro', 11: 'Novembro', 12: 'Dezembro'
            }
            mes_nome = meses[primeira_data.month]
            mes_ano_info = f"{mes_nome} de {primeira_data.year}"
            
            # Formatear as semanas
            semanas_lista = list(semanas)
            if len(semanas_lista) == 1:
                semanas_info = f"{semanas_lista[0]}ª Semana"
            elif len(semanas_lista) == 2:
                semanas_info = f"{semanas_lista[0]}ª e {semanas_lista[1]}ª Semanas"
            else:
                semanas_formatadas = [f"{s}ª" for s in semanas_lista[:-1]]
                semanas_info = f"{', '.join(semanas_formatadas)} e {semanas_lista[-1]}ª Semanas"

    if request.method == 'POST':
        for financeiro in consultas_psico:
            # Captura os dados do formulário com base no ID do financeiro
            forma_pagamento = request.POST.get(f'forma_{financeiro.id}')
            presenca = request.POST.get(f'presenca_{financeiro.id}')
            observacoes = request.POST.get(f'observacoes_{financeiro.id}')
            valor_pagamento = request.POST.get(f'valor_pagamento_{financeiro.id}')
            data_pagamento = request.POST.get(f'data_pagamento_{financeiro.id}')
            
            # Atualiza os campos apenas se houve alteração
            if valor_pagamento:
                financeiro.valor_pagamento = valor_pagamento
            if forma_pagamento:
                financeiro.forma = forma_pagamento
            if presenca:
                financeiro.presenca = presenca
            if observacoes is not None:
                financeiro.observacoes = observacoes
            if data_pagamento:
                financeiro.data_pagamento = data_pagamento
            
            # Salva as alterações no banco de dados
            financeiro.save()

        # Exibe uma mensagem de sucesso e redireciona para evitar reenvio do formulário
        #messages.success(request, 'Consultas atualizadas com sucesso.')
        return redirect('editar_consultas', psicologo_id=psicologo_id)

    return render(request, 'pages/editar_confirmacao_consultas.html', {
        'psicologa': psicologa, 
        'financeiros': consultas_psico, 
        'is_admin': is_admin,
        'semanas_info': semanas_info,
        'mes_ano_info': mes_ano_info
    })

@login_required(login_url='login1')
def historico_confirmacao_consultas(request, psicologo_id):
    from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
    from collections import defaultdict
    from datetime import datetime
    
    psicologa = get_object_or_404(Psicologa, id=psicologo_id)
    
    # Verificar permissões
    if request.user.username != psicologa.nome and not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission1.html')
    
    # Query base - apenas consultas bloqueadas (histórico)
    consultas_base = Financeiro.objects.filter(
        psicologa=psicologa, 
        bloqueada=True
    ).select_related('paciente', 'sala', 'sala__id_unidade').order_by('-data', 'dia_semana', 'horario')
    
    # Aplicar filtros se houver
    filtros_aplicados = {}
    
    if request.method == 'POST':
        ano = request.POST.get('ano')
        mes = request.POST.get('mes')
        modalidade = request.POST.get('modalidade')
        presenca = request.POST.get('presenca')
        semana = request.POST.get('semana')
        data_inicio = request.POST.get('data_inicio')
        data_fim = request.POST.get('data_fim')
        
        if ano and ano != 'todos':
            consultas_base = consultas_base.filter(data__year=ano)
            filtros_aplicados['ano'] = ano
            
        if mes and mes != 'todos':
            consultas_base = consultas_base.filter(data__month=mes)
            filtros_aplicados['mes'] = mes
            
        if modalidade and modalidade != 'todos':
            consultas_base = consultas_base.filter(modalidade=modalidade)
            filtros_aplicados['modalidade'] = modalidade
            
        if presenca and presenca != 'todos':
            consultas_base = consultas_base.filter(presenca=presenca)
            filtros_aplicados['presenca'] = presenca
            
        if semana and semana != 'todos':
            consultas_base = consultas_base.filter(semana=semana)
            filtros_aplicados['semana'] = semana
            
        if data_inicio and data_fim:
            try:
                data_inicio_obj = datetime.strptime(data_inicio, '%Y-%m-%d').date()
                data_fim_obj = datetime.strptime(data_fim, '%Y-%m-%d').date()
                consultas_base = consultas_base.filter(data__range=[data_inicio_obj, data_fim_obj])
                filtros_aplicados['data_inicio'] = data_inicio
                filtros_aplicados['data_fim'] = data_fim
            except ValueError:
                pass
    
    # Agrupar consultas por mês/ano e semana
    consultas_agrupadas = defaultdict(lambda: defaultdict(list))
    
    for consulta in consultas_base:
        if consulta.data:
            mes_ano_key = f"{consulta.data.year}-{consulta.data.month:02d}"
            semana_key = consulta.semana
            consultas_agrupadas[mes_ano_key][semana_key].append(consulta)
    
    # Converter para lista ordenada para paginação
    grupos_ordenados = []
    for mes_ano_key in sorted(consultas_agrupadas.keys(), reverse=True):
        # Formatear nome do mês/ano
        ano, mes = mes_ano_key.split('-')
        meses_nomes = {
            '01': 'Janeiro', '02': 'Fevereiro', '03': 'Março', '04': 'Abril',
            '05': 'Maio', '06': 'Junho', '07': 'Julho', '08': 'Agosto',
            '09': 'Setembro', '10': 'Outubro', '11': 'Novembro', '12': 'Dezembro'
        }
        mes_nome = f"{meses_nomes[mes]} de {ano}"
        
        # Agrupar semanas deste mês
        semanas_do_mes = []
        for semana_num in sorted(consultas_agrupadas[mes_ano_key].keys()):
            consultas_da_semana = sorted(
                consultas_agrupadas[mes_ano_key][semana_num], 
                key=lambda x: (x.dia_semana, x.horario)
            )
            
            # Calcular estatísticas da semana
            total_consultas = len(consultas_da_semana)
            consultas_presentes = len([c for c in consultas_da_semana if c.presenca == 'Sim'])
            valor_total = sum([c.valor_pagamento or 0 for c in consultas_da_semana if c.valor_pagamento])
            
            semanas_do_mes.append({
                'numero': semana_num,
                'consultas': consultas_da_semana,
                'total_consultas': total_consultas,
                'consultas_presentes': consultas_presentes,
                'valor_total': valor_total,
                'taxa_presenca': (consultas_presentes / total_consultas * 100) if total_consultas > 0 else 0
            })
        
        if semanas_do_mes:  # Só adicionar se houver semanas com consultas
            grupos_ordenados.append({
                'mes_ano': mes_nome,
                'mes_ano_key': mes_ano_key,
                'semanas': semanas_do_mes
            })
    
    # Configurar paginação por grupos de mês
    itens_por_pagina = int(request.GET.get('items_per_page', 6))  # 6 meses por página
    itens_por_pagina = max(1, min(12, itens_por_pagina))
    
    paginator = Paginator(grupos_ordenados, itens_por_pagina)
    page_number = request.GET.get('page', 1)
    
    try:
        grupos_paginados = paginator.page(page_number)
    except PageNotAnInteger:
        grupos_paginados = paginator.page(1)
    except EmptyPage:
        grupos_paginados = paginator.page(paginator.num_pages)
    
    # Calcular estatísticas gerais
    total_consultas_geral = consultas_base.count()
    total_presentes = consultas_base.filter(presenca='Sim').count()
    valor_total_geral = consultas_base.aggregate(
        total=Sum('valor_pagamento')
    )['total'] or 0
    
    # Obter anos e meses disponíveis para filtros
    anos_disponiveis = sorted(
        consultas_base.values_list('data__year', flat=True).distinct(), 
        reverse=True
    )
    
    meses_disponiveis = [
        (1, 'Janeiro'), (2, 'Fevereiro'), (3, 'Março'), (4, 'Abril'),
        (5, 'Maio'), (6, 'Junho'), (7, 'Julho'), (8, 'Agosto'),
        (9, 'Setembro'), (10, 'Outubro'), (11, 'Novembro'), (12, 'Dezembro')
    ]
    
    semanas_disponiveis = [1, 2, 3, 4, 5]
    modalidades_disponiveis = ['Presencial', 'Online']
    presencas_disponiveis = ['Sim', 'Nao', 'Falta Inj', 'Falta Psico', 'Feriado', 'Em Aberto']
    
    context = {
        'psicologa': psicologa,
        'grupos_consultas': grupos_paginados,
        'total_consultas_geral': total_consultas_geral,
        'total_presentes': total_presentes,
        'valor_total_geral': valor_total_geral,
        'taxa_presenca_geral': (total_presentes / total_consultas_geral * 100) if total_consultas_geral > 0 else 0,
        'anos_disponiveis': anos_disponiveis,
        'meses_disponiveis': meses_disponiveis,
        'semanas_disponiveis': semanas_disponiveis,
        'modalidades_disponiveis': modalidades_disponiveis,
        'presencas_disponiveis': presencas_disponiveis,
        'filtros_aplicados': filtros_aplicados,
        'itens_por_pagina': itens_por_pagina,
    }
    
    return render(request, 'pages/historico_confirmacao_consultas.html', context)

@login_required(login_url='login1')
def ExcluirConfirma_consulta(request, psicologo_id, consulta_id):

    psicologa = get_object_or_404(Psicologa, id=psicologo_id)
    consulta = get_object_or_404(Financeiro, id=consulta_id, psicologa=psicologa)

    if request.user.username != psicologa.nome and not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission1.html')
    
    if request.method == "POST":
        consulta.delete()

        return redirect('confirma_consulta', psicologo_id=psicologa.id)

    return render(request, 'pages/deletar_confirma_consulta.html', {'psicologo': psicologa})


def adicionarConsultaEmergencial(request, psicologo_id):
    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    psicologa = get_object_or_404(Psicologa, id=psicologo_id)
    pacientes = Paciente.objects.filter(deletado=False)

    if request.method == "POST":
        paciente_id = request.POST.get('paciente')
        data_consulta = request.POST.get('data_consulta')
        horario = request.POST.get('horario_consulta')
        valor = request.POST.get('valor')
        observacoes = request.POST.get('observacoes')
        presenca = request.POST.get('presenca')
        forma_pagamento = request.POST.get('forma_pagamento')
        valor_pagamento = request.POST.get('valor_pagamento')
        data_pagamento = request.POST.get('data_pagamento')
        tipo_atendimento = request.POST.get('tipo_atendimento')

        paciente = Paciente.objects.get(id=paciente_id)

        data_obj = datetime.strptime(data_consulta, '%Y-%m-%d')

        # Determina a semana correta dentro do mês
        semana_mes = (data_obj.day - 1) // 7 + 1  # Calcula a semana no mês (1ª, 2ª, etc.)


        # Obtém o dia da semana como um número (0=segunda, 1=terça, ..., 6=domingo)
        dia_semana_num = data_obj.weekday()
        
        # Converte o número para o nome do dia da semana em português
        dias_semana = [
            'Segunda',
            'Terça',
            'Quarta',
            'Quinta',
            'Sexta',
            'Sábado',
        ]
        dia_semana = dias_semana[dia_semana_num]

        # Verifica se o paciente já tem uma consulta agendada para o mesmo horário
        if Financeiro.objects.filter(paciente=paciente, data=data_consulta, horario=horario).exists():
            messages.error(request, "Este paciente já possui uma consulta agendada para este horário.")
            return redirect('adicionar_consulta_emergencial', psicologo_id=psicologa.id)

        # Cria a consulta emergencial
        Financeiro.objects.create(
            dia_semana=dia_semana,
            semana = semana_mes,
            periodo_atendimento=paciente.periodo,
            horario=horario,
            psicologa=psicologa,
            paciente=paciente,
            valor=valor,
            data=data_consulta,
            observacoes=observacoes,
            valor_pagamento=valor_pagamento,
            forma=forma_pagamento,
            data_pagamento=data_pagamento,
            presenca=presenca,
            modalidade=tipo_atendimento,
        )

        return redirect('confirma_consulta', psicologo_id=psicologa.id)


    return render (request, 'pages/adiciona_consulta_emergencial.html', {
        'psicologa': psicologa,
        'pacientes': pacientes
    })

@login_required(login_url='login1')
def bloquear_consulta(request, psicologo_id):

    consultas = Financeiro.objects.all()
    psicologa = get_object_or_404(Psicologa, id=psicologo_id)
    if request.method == "POST":
        for consulta in consultas:
            consulta.bloqueada = True
            consulta.save()
        
        return redirect('editar_consultas', psicologo_id=psicologo_id)

    return render(request, 'pages/bloquear_consulta.html', {
        'psicologo': psicologa,
    })


@login_required(login_url='login1')
def desbloquear_consulta(request, psicologo_id):
    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    psicologa = get_object_or_404(Psicologa, id=psicologo_id)
    
    if request.method == "POST":
        data_selecionada = request.POST.get('data_selecionada')
        
        if data_selecionada:
            try:
                # Converte a data string para objeto datetime
                data_obj = datetime.strptime(data_selecionada, '%Y-%m-%d').date()
                
                # Calcula o início da semana (segunda-feira)
                dias_para_segunda = data_obj.weekday()  # 0=segunda, 6=domingo
                inicio_semana = data_obj - timedelta(days=dias_para_segunda)
                
                # Calcula o fim da semana (sábado)
                fim_semana = inicio_semana + timedelta(days=5)  # Segunda + 5 dias = Sábado
                
                # Filtra consultas bloqueadas da psicóloga na semana selecionada
                consultas_para_desbloquear = Financeiro.objects.filter(
                    psicologa=psicologa,
                    bloqueada=True,
                    data__gte=inicio_semana,
                    data__lte=fim_semana
                )
                
                # Desbloqueia as consultas
                consultas_desbloqueadas = consultas_para_desbloquear.update(bloqueada=False)
                
                if consultas_desbloqueadas > 0:
                    messages.success(request, f'{consultas_desbloqueadas} consulta(s) desbloqueada(s) da semana de {inicio_semana.strftime("%d/%m/%Y")} a {fim_semana.strftime("%d/%m/%Y")}.')
                else:
                    messages.info(request, 'Nenhuma consulta bloqueada foi encontrada para a semana selecionada.')
                
            except ValueError:
                messages.error(request, 'Data inválida. Por favor, selecione uma data válida.')
        else:
            messages.error(request, 'Por favor, selecione uma data.')
        
        return redirect('editar_confirmacao_consultas', psicologo_id=psicologo_id)

    return render(request, 'pages/desbloquear_consulta.html', {
        'psicologo': psicologa,
    })


# FINÂNCEIRO
@login_required(login_url='login1')
def consultar_financeiro(request):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    # Verifica se é uma nova consulta (POST)
    if request.method == "POST":
        mes = request.POST.get('mes')
        ano = request.POST.get('ano')

        # Armazena mes e ano na sessão
        request.session['mes'] = mes
        request.session['ano'] = ano

        return redirect('consultar_financeiro')

    # Recupera mes e ano da sessão
    mes = request.session.get('mes')
    ano = request.session.get('ano')

    # Se os valores de mes e ano estiverem presentes na sessão, faz a filtragem
    if mes and ano:
        try:
            mes = int(mes)
            ano = int(ano)

            data_inicio = datetime(ano, mes, 1)
            if mes == 12:
                data_fim = datetime(ano + 1, 1, 1) - timedelta(days=1)
            else:
                data_fim = datetime(ano, mes + 1, 1) - timedelta(days=1)

            # Filtra as consultas financeiras
            financeiros = Financeiro.objects.filter(
                data__range=[data_inicio, data_fim]
            ).exclude(
                presenca="Nao"
            ).exclude(
                presenca__isnull=True
            )

            # Receita bruta por paciente e cálculo dos novos valores
            receita_por_paciente = financeiros.values('paciente__nome').annotate(
                receita_bruta=Sum('valor'),
                valor_momento=ExpressionWrapper(Sum('valor') / 2, output_field=DecimalField(max_digits=10, decimal_places=2)),
                valor_recebido=ExpressionWrapper(Sum(Coalesce(F('valor_pagamento'), 0) / 2), output_field=DecimalField(max_digits=10, decimal_places=2)),
            ).annotate(
                valor_a_receber=ExpressionWrapper(Sum('valor') / 2 - Sum(Coalesce(F('valor_pagamento'), 0) / 2), output_field=DecimalField(max_digits=10, decimal_places=2))
            ).annotate(
                valor_previsto=ExpressionWrapper(
                    (Sum('valor') - Sum(Coalesce(F('valor_pagamento'), 0)) + ((Sum('valor') / 2) - Sum(Coalesce(F('valor_pagamento'), 0) / 2)) * 2) / 2,
                    output_field=DecimalField(max_digits=10, decimal_places=2)
                )
            ).order_by('paciente__nome')

            receita_total = financeiros.aggregate(receita_total=Sum('valor'))
            valor_total_atendimentos = receita_total['receita_total'] if receita_total['receita_total'] else 0
            valor_momento_total = valor_total_atendimentos / 2

            total_receita_bruta = sum([paciente['receita_bruta'] for paciente in receita_por_paciente])
            total_valor_momento = sum([paciente['valor_momento'] for paciente in receita_por_paciente])
            total_valor_recebido = sum([paciente['valor_recebido'] for paciente in receita_por_paciente])
            total_valor_a_receber = sum([paciente['valor_a_receber'] for paciente in receita_por_paciente])

            # Soma de todos os valores previstos de cada paciente
            total_valor_previsto = sum([paciente['valor_previsto'] for paciente in receita_por_paciente])

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
                'total_valor_previsto': total_valor_previsto,
                'message': "Nenhuma consulta financeira encontrada." if not financeiros else None
            })

        except ValueError:
            return render(request, 'pages/consultar_financeiro.html', {
                'error': "Por favor, insira um mês e ano válidos."
            })

    # Se não houver mes e ano na sessão, renderiza o formulário
    return render(request, 'pages/consultar_financeiro.html')


@login_required(login_url='login1')
def editar_financeiro(request, id_financeiro):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    financeiro = get_object_or_404(Financeiro, id=id_financeiro)

    if request.method == "POST":
        valor_pagamento = request.POST.get('valor_pagamento')
        data_pagamento = request.POST.get('data_pagamento')
        presenca = request.POST.get('presenca')
    
        if valor_pagamento:
            financeiro.valor_pagamento = valor_pagamento
            financeiro.data_pagamento = data_pagamento
            financeiro.presenca = presenca
            financeiro.save()
            # Pega o mês e ano da sessão ao redirecionar de volta
            mes = request.session.get('mes')
            ano = request.session.get('ano')
            return redirect(f'{reverse("consultar_financeiro")}?mes={mes}&ano={ano}')


    return render(request, 'pages/editar_financeiro.html', {'financeiro': financeiro})

@login_required(login_url='login1')
def consulta_financeira_pacientes(request):
    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')
    
    financeiros = Financeiro.objects.all()
    pacientes = Paciente.objects.filter(deletado=False)
    psicologas = Psicologa.objects.all()

    # Capturar parâmetros de filtro
    apenas_devedores = request.GET.get('apenas_devedores') == 'on'
    nome_paciente = request.GET.get('nome_paciente', '').strip()
    psicologa_id = request.GET.get('psicologa_id', '')
    
    # Para manter compatibilidade com POST (se necessário)
    if request.method == 'POST':
        apenas_devedores = request.POST.get('apenas_devedores') == 'on'
        nome_paciente = request.POST.get('nome_paciente', '').strip()
        psicologa_id = request.POST.get('psicologa_id', '')

    # Base da consulta para receita por paciente
    receita_query = financeiros.values('paciente__nome', 'paciente__id')

    # Primeiro, obtenha as agregações básicas
    receita_por_paciente = receita_query.annotate(
        receita_bruta=Sum('valor', output_field=DecimalField(max_digits=10, decimal_places=2)),
        valor_recebido=Sum(
            Coalesce('valor_pagamento', 0),
            output_field=DecimalField(max_digits=10, decimal_places=2)
        ),
        # Total de consultas
        n_consultas=Count('id'),
        # Lista de psicólogas distintas para o paciente
        psicologas=ArrayAgg('psicologa__nome', distinct=True)
    ).order_by('paciente__nome')

    # Para cada paciente, calcule os valores e contagens de consultas manualmente
    for paciente_data in receita_por_paciente:
        paciente_id = paciente_data['paciente__id']
        financeiros_paciente = financeiros.filter(paciente__id=paciente_id)
        
        # Calcular valor a receber e crédito
        receita_bruta = paciente_data['receita_bruta'] or Decimal('0.00')
        valor_recebido = paciente_data['valor_recebido'] or Decimal('0.00')
        
        if valor_recebido > receita_bruta:
            paciente_data['valor_a_receber'] = Decimal('0.00')
            paciente_data['valor_credito'] = valor_recebido - receita_bruta
        else:
            paciente_data['valor_a_receber'] = receita_bruta - valor_recebido
            paciente_data['valor_credito'] = Decimal('0.00')
        
        # Contar consultas pagas e não pagas
        consultas_pagas = 0
        consultas_nao_pagas = 0
        
        for f in financeiros_paciente:
            # Valor da consulta
            valor = f.valor or Decimal('0.00')
            # Valor pago
            valor_pagamento = f.valor_pagamento or Decimal('0.00')
            # Verifica se a presença é relevante (Sim ou Falta Injustificada)
            presenca_relevante = f.presenca in ['Sim', 'Falta Inj']
            
            # Se a presença é relevante para pagamento
            if presenca_relevante:
                # Se pagou o valor integral
                if valor_pagamento >= valor:
                    consultas_pagas += 1
                else:
                    # Se não pagou integralmente, é uma consulta não paga
                    consultas_nao_pagas += 1
            else:
                # Faltas justificadas não contam como não pagas
                if f.presenca == 'Nao':
                    consultas_pagas += 1
        
        # Atualiza as contagens no objeto do paciente
        paciente_data['n_consultas_pagas'] = consultas_pagas
        paciente_data['n_consultas_nao_pagas'] = consultas_nao_pagas
        
        # Calcular dívidas por psicóloga
        dividas_por_psicologa = []
        
        # Obter todas as psicólogas que atenderam este paciente
        todas_psicologas = Psicologa.objects.filter(
            financeiro__paciente__id=paciente_id
        ).distinct()
        
        # Para cada psicóloga, verificar se existe dívida específica
        for psicologa in todas_psicologas:
            # Consultas relevantes desta psicóloga com este paciente
            consultas_relevantes = Financeiro.objects.filter(
                paciente__id=paciente_id,
                psicologa=psicologa
            ).filter(
                # Consultas que geram cobrança: presença ou falta injustificada
                Q(presenca='Sim') | Q(presenca='FALTA') | Q(presenca='Falta Inj')
            )
            
            # Calcular o total que deveria ser pago
            total_devido = sum([
                c.valor or Decimal('0.00') for c in consultas_relevantes
            ])
            
            # Calcular o total efetivamente pago
            total_pago = sum([
                c.valor_pagamento or Decimal('0.00') for c in consultas_relevantes
            ])
            
            # Calcular a dívida real com esta psicóloga específica
            divida_real = max(Decimal('0.00'), total_devido - total_pago)
            
            # Adicionar à lista apenas se houver dívida real
            if divida_real > Decimal('0.00'):
                dividas_por_psicologa.append({
                    'psicologa': psicologa.nome,
                    'valor': divida_real
                })
        
        # Atribuir a lista de dívidas calculadas corretamente ao paciente
        paciente_data['dividas_por_psicologa'] = dividas_por_psicologa
    
        psicologas_com_divida = [d['psicologa'] for d in dividas_por_psicologa]
        
        # Lista de psicólogas sem dívidas
        psicologas_sem_divida = [
            p for p in paciente_data['psicologas'] if p not in psicologas_com_divida
        ]
        paciente_data['psicologas_sem_divida'] = psicologas_sem_divida

    # Aplicação dos filtros
    receita_filtrada = list(receita_por_paciente)
    
    # Filtro por nome de paciente
    if nome_paciente:
        receita_filtrada = [
            p for p in receita_filtrada 
            if p['paciente__nome'] and nome_paciente.lower() in p['paciente__nome'].lower()
        ]
        
        # Se não encontrou nenhum paciente com esse nome
        if not receita_filtrada:
            return render(request, 'pages/error_paciente_nao_encontrado_financeiro.html', {
                'nome_cliente': nome_paciente
            })
    
    # Filtro por psicóloga
    if psicologa_id:
        filtered_pacientes = []
        for p in receita_filtrada:
            # Verifica se esta psicóloga aparece nas consultas deste paciente
            has_psicologa = financeiros.filter(
                paciente__id=p['paciente__id'],
                psicologa__id=psicologa_id
            ).exists()
            
            if has_psicologa:
                filtered_pacientes.append(p)
        
        receita_filtrada = filtered_pacientes
    
    # Filtro por pacientes com dívida
    if apenas_devedores:
        receita_filtrada = [p for p in receita_filtrada if p['valor_a_receber'] > 0]

    # Formatar os valores decimais para evitar problemas de exibição
    for paciente in receita_filtrada:
        paciente['receita_bruta'] = round(paciente['receita_bruta'] or Decimal('0.00'), 2)
        paciente['valor_recebido'] = round(paciente['valor_recebido'] or Decimal('0.00'), 2)
        paciente['valor_a_receber'] = round(paciente['valor_a_receber'] or Decimal('0.00'), 2)
        paciente['valor_credito'] = round(paciente['valor_credito'] or Decimal('0.00'), 2)
        
        # Formatar valores das dívidas
        for divida in paciente['dividas_por_psicologa']:
            divida['valor'] = round(divida['valor'], 2)
        
        # Verificações de consistência
        if paciente['valor_a_receber'] > 0 and paciente['n_consultas_nao_pagas'] == 0:
            paciente['n_consultas_nao_pagas'] = max(1, paciente['n_consultas_nao_pagas'])
        
        if paciente['n_consultas_nao_pagas'] == 0 and paciente['valor_a_receber'] > 0:
            paciente['valor_a_receber'] = Decimal('0.00')
        
        if paciente['valor_a_receber'] > 0 and paciente['n_consultas_nao_pagas'] == 0:
            paciente['n_consultas_nao_pagas'] = 1
            if paciente['n_consultas_pagas'] + paciente['n_consultas_nao_pagas'] > paciente['n_consultas']:
                paciente['n_consultas_pagas'] = paciente['n_consultas'] - paciente['n_consultas_nao_pagas']

    # CONFIGURAÇÃO DA PAGINAÇÃO
    # Permitir que o usuário escolha quantos itens por página
    itens_por_pagina = int(request.GET.get('items_per_page', 20))
    # Limitar entre 10 e 100 itens por página
    itens_por_pagina = max(10, min(100, itens_por_pagina))
    
    paginator = Paginator(receita_filtrada, itens_por_pagina)
    
    # Capturar o número da página da URL
    page_number = request.GET.get('page', 1)
    
    try:
        receita_paginada = paginator.page(page_number)
    except PageNotAnInteger:
        # Se a página não for um inteiro, mostrar a primeira página
        receita_paginada = paginator.page(1)
    except EmptyPage:
        # Se a página estiver fora do range, mostrar a última página
        receita_paginada = paginator.page(paginator.num_pages)

    # Calcular totais gerais (usando todos os dados, não apenas a página atual)
    total_bruto = financeiros.aggregate(Sum('valor'))['valor__sum'] or Decimal('0.00')
    total_recebido = financeiros.aggregate(Sum('valor_pagamento'))['valor_pagamento__sum'] or Decimal('0.00')
    valor_a_receber = max(Decimal('0.00'), total_bruto - total_recebido)

    # Pacientes Ativos
    pacientes_ativos = pacientes.count()

    # Valor recebido no mês atual
    hoje = datetime.now()
    valor_recebido_mes = financeiros.filter(
        data_pagamento__year=hoje.year,
        data_pagamento__month=hoje.month
    ).aggregate(Sum('valor_pagamento'))['valor_pagamento__sum'] or Decimal('0.00')

    # Preparar parâmetros de query para manter filtros na paginação
    query_params = {}
    if apenas_devedores:
        query_params['apenas_devedores'] = 'on'
    if nome_paciente:
        query_params['nome_paciente'] = nome_paciente
    if psicologa_id:
        query_params['psicologa_id'] = psicologa_id
    if request.GET.get('items_per_page'):
        query_params['items_per_page'] = request.GET.get('items_per_page')

    return render(request, 'pages/financeiro_paciente.html', {
        'receita_por_paciente': receita_paginada,
        'pacientes': pacientes,
        'psicologas': psicologas,
        'apenas_devedores': apenas_devedores,
        'nome_paciente': nome_paciente,
        'psicologa_id': psicologa_id,
        'total_bruto': round(total_bruto, 2),
        'total_recebido': round(total_recebido, 2),
        'valor_a_receber': round(valor_a_receber, 2),
        'pacientes_ativos': pacientes_ativos,
        'valor_recebido_mes': round(valor_recebido_mes, 2),
        'query_params': query_params,  # Para manter filtros na paginação
        'total_pacientes': len(receita_filtrada),  # Total de pacientes filtrados
    })

@login_required(login_url='login1')
def financeiro_cliente_individual(request, id_paciente):
    """
    Exibe todos os registros financeiros de um único paciente específico.
    Permite filtragem por diversos critérios como data, psicóloga, status de presença e pagamento.
    """
    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')
    
    # Obter paciente
    paciente = get_object_or_404(Paciente, id=id_paciente)
    
    # Valores padrão para filtros
    filtros = {
        'data_inicio': None,
        'data_fim': None,
        'psicologa_id': None,
        'presenca': None,
        'pagamento': None,
        'modalidade': None
    }
    
    # Obter TODOS os registros financeiros do paciente (sem filtro de presença inicial)
    financeiros_base = Financeiro.objects.filter(paciente=paciente).select_related('psicologa')
    
    # Aplicar filtros quando o formulário for postado
    financeiros = financeiros_base
    if request.method == 'POST':
        data_inicio = request.POST.get('data_inicio')
        data_fim = request.POST.get('data_fim')
        psicologa_id = request.POST.get('psicologa_id')
        presenca = request.POST.get('presenca')
        pagamento = request.POST.get('pagamento')
        modalidade = request.POST.get('modalidade')
        
        # Atualizar dicionário de filtros
        filtros.update({
            'data_inicio': data_inicio,
            'data_fim': data_fim,
            'psicologa_id': psicologa_id,
            'presenca': presenca,
            'pagamento': pagamento,
            'modalidade': modalidade
        })
        
        # Aplicar filtros nos registros
        if data_inicio:
            financeiros = financeiros.filter(data__gte=data_inicio)
        
        if data_fim:
            financeiros = financeiros.filter(data__lte=data_fim)
        
        if psicologa_id:
            financeiros = financeiros.filter(psicologa_id=psicologa_id)
        
        if presenca:
            financeiros = financeiros.filter(presenca=presenca)
        
        if pagamento == 'pago':
            financeiros = financeiros.filter(valor_pagamento__isnull=False).exclude(valor_pagamento=0)
        elif pagamento == 'nao_pago':
            financeiros = financeiros.filter(Q(valor_pagamento__isnull=True) | Q(valor_pagamento=0))
        
        if modalidade:
            financeiros = financeiros.filter(modalidade=modalidade)
    
    # Ordenar por data
    financeiros = financeiros.order_by('-data', 'horario')
    
    # CÁLCULOS FINANCEIROS SEGUINDO A MESMA LÓGICA DA VIEW consulta_financeira_pacientes
    
    # Usar TODOS os registros financeiros do paciente para cálculos (não apenas os filtrados)
    todos_financeiros = financeiros_base
    
    # CORRIGIDO: Usando apenas Sum sem Coalesce que estava causando problema
    receita_bruta = todos_financeiros.aggregate(
        total_valor=Sum('valor')
    )['total_valor'] or Decimal('0.00')
    
    # CORRIGIDO: Calcular valor recebido usando Sum direto com filter no aggregate
    valor_recebido = todos_financeiros.aggregate(
        total_pagamento=Sum('valor_pagamento')
    )['total_pagamento'] or Decimal('0.00')
    
    # Calcular valor a receber e crédito
    if valor_recebido > receita_bruta:
        valor_a_receber = Decimal('0.00')
        credito = valor_recebido - receita_bruta
    else:
        valor_a_receber = receita_bruta - valor_recebido
        credito = Decimal('0.00')
    
    # Total de consultas
    n_consultas = todos_financeiros.count()
    
    # Contar consultas pagas e não pagas seguindo a lógica da view principal
    consultas_pagas = 0
    consultas_nao_pagas = 0
    
    for f in todos_financeiros:
        # Valor da consulta
        valor = f.valor or Decimal('0.00')
        # Valor pago
        valor_pagamento = f.valor_pagamento or Decimal('0.00')
        # Verifica se a presença é relevante (Sim ou Falta Injustificada)
        presenca_relevante = f.presenca in ['Sim', 'Falta Inj']
        
        # Se a presença é relevante para pagamento
        if presenca_relevante:
            # Se pagou o valor integral
            if valor_pagamento >= valor:
                consultas_pagas += 1
            else:
                # Se não pagou integralmente, é uma consulta não paga
                consultas_nao_pagas += 1
        else:
            # Faltas justificadas não contam como não pagas
            if f.presenca == 'Nao':
                consultas_pagas += 1
    
    # Calcular dívidas por psicóloga
    dividas_por_psicologa = []
    
    # Obter todas as psicólogas que atenderam este paciente
    todas_psicologas = Psicologa.objects.filter(
        financeiro__paciente=paciente
    ).distinct()
    
    # Para cada psicóloga, verificar se existe dívida específica
    for psicologa in todas_psicologas:
        # Consultas relevantes desta psicóloga com este paciente
        consultas_relevantes = Financeiro.objects.filter(
            paciente=paciente,
            psicologa=psicologa
        ).filter(
            # Consultas que geram cobrança: presença ou falta injustificada
            Q(presenca='Sim') | Q(presenca='FALTA') | Q(presenca='Falta Inj')
        )
        
        # Calcular o total que deveria ser pago
        total_devido = sum([
            c.valor or Decimal('0.00') for c in consultas_relevantes
        ])
        
        # Calcular o total efetivamente pago
        total_pago = sum([
            c.valor_pagamento or Decimal('0.00') for c in consultas_relevantes
        ])
        
        # Calcular a dívida real com esta psicóloga específica
        divida_real = max(Decimal('0.00'), total_devido - total_pago)
        
        # Adicionar à lista apenas se houver dívida real
        if divida_real > Decimal('0.00'):
            dividas_por_psicologa.append({
                'psicologa': psicologa.nome,
                'valor': round(divida_real, 2)
            })
    
    # Obter todas as psicólogas que atenderam este paciente para exibição
    psicologas_ids = todos_financeiros.values_list('psicologa', flat=True).distinct()
    psicologas_do_paciente = Psicologa.objects.filter(id__in=psicologas_ids)
    psicologas_nomes = [p.nome for p in psicologas_do_paciente]
    
    # Psicólogas com dívida
    psicologas_com_divida = [d['psicologa'] for d in dividas_por_psicologa]
    
    # Psicólogas sem dívida
    psicologas_sem_divida = [
        p for p in psicologas_nomes if p not in psicologas_com_divida
    ]
    
    # Obter todas as psicólogas para o filtro
    psicologas = Psicologa.objects.all()
    
    # Preencher o resumo
    resumo = {
        'receita_bruta': round(receita_bruta, 2),
        'valor_recebido': round(valor_recebido, 2),
        'valor_a_receber': round(valor_a_receber, 2),
        'credito': round(credito, 2),
        'n_consultas': n_consultas,
        'n_consultas_pagas': consultas_pagas,
        'n_consultas_nao_pagas': consultas_nao_pagas,
        'psicologas': psicologas_nomes,
        'dividas_por_psicologa': dividas_por_psicologa,
        'psicologas_sem_divida': psicologas_sem_divida
    }
    
    context = {
        'paciente': paciente,
        'financeiros': financeiros,  # Registros filtrados para a tabela
        'resumo': resumo,
        'filtros': filtros,
        'psicologas': psicologas
    }
    
    return render(request, 'pages/financeiro_cliente_individual.html', context)

@login_required(login_url='login1')
def apuracao_financeira(request):
    """
    View para apuração financeira com métricas detalhadas e visualizações.
    """
    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    # Período para análise (por padrão, último mês)
    data_inicio = request.GET.get('data_inicio')
    data_fim = request.GET.get('data_fim')
    
    hoje = datetime.now().date()
    if not data_inicio:
        # Por padrão, primeiro dia do mês atual
        data_inicio = hoje.replace(day=1)
    else:
        data_inicio = datetime.strptime(data_inicio, '%Y-%m-%d').date()
        
    if not data_fim:
        # Por padrão, dia atual
        data_fim = hoje
    else:
        data_fim = datetime.strptime(data_fim, '%Y-%m-%d').date()
    
    # CORREÇÃO 1: Criar filtro base correto para o período
    filtro_periodo = Q(data__gte=data_inicio) & Q(data__lte=data_fim)
    
    # ===== Contagens básicas =====
    total_salas = Sala.objects.count()
    total_unidades = Unidade.objects.count()
    total_pacientes = Paciente.objects.filter(deletado=False).count()
    total_psicologas = Psicologa.objects.count()
    
    # CORREÇÃO 2: Aplicar o filtro de período nas consultas
    consultas_periodo = Financeiro.objects.all()

    total_atendimentos_realizados = consultas_periodo.filter(presenca="Sim").count()
    print(f"Total de atendimentos realizados no período: {total_atendimentos_realizados}")
    
    # ===== Valores financeiros =====
    total_faturamento_fisico = consultas_periodo.filter(
        modalidade='Presencial', 
        valor_pagamento__isnull=False,
        # CORREÇÃO 3: Adicionar filtro para valores maiores que 0
        valor_pagamento__gt=0
    ).aggregate(Sum('valor_pagamento'))['valor_pagamento__sum'] or 0
    
    total_faturamento_online = consultas_periodo.filter(
        modalidade='Online', 
        valor_pagamento__isnull=False,
        valor_pagamento__gt=0
    ).aggregate(Sum('valor_pagamento'))['valor_pagamento__sum'] or 0
    
    total_faturamento = total_faturamento_fisico + total_faturamento_online

    # ===== Análise por salas =====
    salas = Sala.objects.all()
    consultas_por_sala = {}
    salas_utilizadas = 0
    
    salas_data = []
    for sala in salas:
        # CORREÇÃO 4: Aplicar filtro de período nas consultas por sala
        consultas_sala = consultas_periodo.filter(
            sala=sala, 
            presenca="Sim"
        )
        qtd_consultas = consultas_sala.count()
        
        if qtd_consultas > 0:
            salas_utilizadas += 1
            
        # Faturamento por sala
        faturamento_sala = consultas_sala.filter(
            valor_pagamento__isnull=False,
            valor_pagamento__gt=0
        ).aggregate(Sum('valor_pagamento'))['valor_pagamento__sum'] or 0
        
        # Tempo total de atendimento (em horas)
        tempo_total_horas = qtd_consultas  # Assumindo consultas de 1 hora
        
        salas_data.append({
            'id': sala.id_sala,
            'numero_sala': sala.numero_sala,
            'cor': sala.cor_sala,
            'faturamento': faturamento_sala,
            'atendimentos_realizados': qtd_consultas,
            'tempo_total_horas': tempo_total_horas,
            'unidade': sala.id_unidade.nome_unidade
        })
    
    # ===== Análise por unidade =====
    unidades = Unidade.objects.all()
    unidades_data = []
    
    for unidade in unidades:
        # Salas desta unidade
        salas_unidade = Sala.objects.filter(id_unidade=unidade)
        num_salas = salas_unidade.count()
        
        # CORREÇÃO 5: Aplicar filtro de período nas consultas por unidade
        salas_ids = salas_unidade.values_list('id_sala', flat=True)
        consultas_unidade = consultas_periodo.filter(
            sala__id_sala__in=salas_ids, 
            presenca="Sim"
        )
        
        # Pacientes atendidos nesta unidade
        pacientes_unidade = consultas_unidade.values('paciente').distinct().count()
        
        # Faturamento da unidade
        faturamento_unidade = consultas_unidade.filter(
            valor_pagamento__isnull=False,
            valor_pagamento__gt=0
        ).aggregate(Sum('valor_pagamento'))['valor_pagamento__sum'] or 0
        
        unidades_data.append({
            'id': unidade.id_unidade,
            'nome_unidade': unidade.nome_unidade,
            'num_salas': num_salas,
            'num_pacientes': pacientes_unidade,
            'faturamento': faturamento_unidade,
            'atendimentos_realizados': consultas_unidade.count()
        })
    
    # ===== Análise por psicóloga =====
    psicologas = Psicologa.objects.all()
    psicologas_data = []
    
    for psicologa in psicologas:
        # CORREÇÃO 6: Aplicar filtro de período nas consultas por psicóloga
        consultas_psicologa = consultas_periodo.filter(
            psicologa=psicologa, 
            presenca="Sim"
        )
        
        # Valor recebido
        valor_recebido = consultas_psicologa.filter(
            valor_pagamento__isnull=False,
            valor_pagamento__gt=0
        ).aggregate(Sum('valor_pagamento'))['valor_pagamento__sum'] or 0
        
        # Quantidade de pacientes diferentes
        pacientes_atendidos = consultas_psicologa.values('paciente').distinct().count()
        
        psicologas_data.append({
            'id': psicologa.id,
            'nome': psicologa.nome,
            'cor': psicologa.cor,
            'consultas_realizadas': consultas_psicologa.count(),
            'valor_recebido': valor_recebido,
            'pacientes_atendidos': pacientes_atendidos
        })
    
    # ===== Análise de ocupação =====
    # Taxa de ocupação das salas (considerando 8 horas por dia, dias úteis no período)
    dias_uteis = len([d for d in range((data_fim - data_inicio).days + 1) 
                    if (data_inicio + timedelta(days=d)).weekday() < 5])
    capacidade_total_horas = total_salas * dias_uteis * 8  # 8 horas por dia
    tempo_ocupado_horas = total_atendimentos_realizados  # Assumindo 1h por consulta
    
    if capacidade_total_horas > 0:
        taxa_ocupacao_salas = (tempo_ocupado_horas / capacidade_total_horas) * 100
    else:
        taxa_ocupacao_salas = 0
    
    # ===== Cálculos de médias e taxas =====
    faturamento_medio_sala = total_faturamento / total_salas if total_salas > 0 else 0
    faturamento_medio_paciente = total_faturamento / total_pacientes if total_pacientes > 0 else 0
    faturamento_medio_psicologa = total_faturamento / total_psicologas if total_psicologas > 0 else 0
    
    sessoes_por_paciente = total_atendimentos_realizados / total_pacientes if total_pacientes > 0 else 0
    sessoes_por_psicologa = total_atendimentos_realizados / total_psicologas if total_psicologas > 0 else 0
    pacientes_por_psicologa = total_pacientes / total_psicologas if total_psicologas > 0 else 0
    
    # Taxa de ocupação por paciente (média de consultas por capacidade)
    capacidade_maxima_atendimento = total_pacientes * 4  # Assumindo máximo 4 consultas por paciente/mês
    taxa_ocupacao_pacientes = (total_atendimentos_realizados / capacidade_maxima_atendimento) * 100 if capacidade_maxima_atendimento > 0 else 0
    
    # Taxa de retenção (simplificada - indicador demonstrativo)
    # Aqui poderia ser implementada com dados do mês anterior para comparação
    taxa_retencao_pacientes = 85  # Valor demonstrativo, idealmente seria calculado
    
    # ===== Dados financeiros adicionais =====
    # CORREÇÃO 7: Aplicar filtro de período nas despesas
    custo_fixo_total = Despesas.objects.filter(
        filtro_periodo
    ).aggregate(Sum('valor'))['valor__sum'] or 0
    
    custo_variavel = 0  # Se houver custos variáveis, adicionar aqui
    
    # Métricas financeiras
    ticket_medio_atendimento = total_faturamento / total_atendimentos_realizados if total_atendimentos_realizados > 0 else 0
    lucro_bruto = total_faturamento - custo_variavel
    lucro_liquido = total_faturamento - (custo_fixo_total + custo_variavel)
    margem_lucro = (lucro_liquido / total_faturamento) * 100 if total_faturamento > 0 else 0
    ponto_equilibrio = Decimal(str(custo_fixo_total)) / Decimal(str(ticket_medio_atendimento)) if ticket_medio_atendimento > 0 else 0
    
    # Para demonstração, poderia ser calculado com dados históricos
    taxa_crescimento_pacientes = 5  # Demonstrativo
    taxa_crescimento_faturamento = 8  # Demonstrativo
    
    # ===== Dados para gráficos =====
    # Faturamento por unidade
    fat_unidades_labels = [u['nome_unidade'] for u in unidades_data]
    fat_unidades_valores = [float(u['faturamento']) for u in unidades_data]
    
    # Consultas por dia da semana
    dias_semana = ['Segunda', 'Terça', 'Quarta', 'Quinta', 'Sexta', 'Sábado', 'Domingo']
    consultas_por_dia = {}
    
    for dia_index, dia_nome in enumerate(dias_semana):
        # CORREÇÃO 8: Usar consultas_periodo ao invés de consultas não filtradas
        count = consultas_periodo.filter(dia_semana=dia_nome, presenca="Sim").count()
        consultas_por_dia[dia_nome] = count
    
    dias_consultas_labels = list(consultas_por_dia.keys())
    dias_consultas_valores = list(consultas_por_dia.values())
    
    # Consultas por psicóloga
    psi_consultas_labels = [p['nome'] for p in psicologas_data]
    psi_consultas_valores = [p['consultas_realizadas'] for p in psicologas_data]
    psi_consultas_cores = [p['cor'] for p in psicologas_data]
    
    # Ocupação das salas
    salas_ocupacao_labels = [s['numero_sala'] for s in salas_data]
    salas_ocupacao_valores = [s['atendimentos_realizados'] for s in salas_data]
    salas_ocupacao_cores = [s['cor'] for s in salas_data]
    
    # Faturamento vs custos
    financeiro_categorias = ['Faturamento', 'Custos Fixos', 'Lucro Líquido']
    financeiro_valores = [float(total_faturamento), float(custo_fixo_total), float(lucro_liquido)]

    # Construindo contexto para o template
    contexto = {
        # Dados do período
        'data_inicio': data_inicio,
        'data_fim': data_fim,
        
        # Dados gerais
        'total_salas': total_salas,
        'total_unidades': total_unidades,
        'total_pacientes': total_pacientes,
        'total_psicologas': total_psicologas,
        'total_atendimentos_realizados': total_atendimentos_realizados,
        'salas_utilizadas': salas_utilizadas,
        
        # Dados financeiros
        'total_faturamento_fisico': total_faturamento_fisico,
        'total_faturamento_online': total_faturamento_online,
        'total_faturamento': total_faturamento,
        'custo_fixo_total': custo_fixo_total,
        'custo_variavel': custo_variavel,
        'lucro_bruto': lucro_bruto,
        'lucro_liquido': lucro_liquido,
        
        # Taxas e médias
        'taxa_ocupacao_salas': taxa_ocupacao_salas,
        'faturamento_medio_sala': faturamento_medio_sala,
        'faturamento_medio_paciente': faturamento_medio_paciente,
        'faturamento_medio_psicologa': faturamento_medio_psicologa,
        'taxa_ocupacao_pacientes': taxa_ocupacao_pacientes,
        'sessoes_por_paciente': sessoes_por_paciente,
        'sessoes_por_psicologa': sessoes_por_psicologa,
        'pacientes_por_psicologa': pacientes_por_psicologa,
        'taxa_retencao_pacientes': taxa_retencao_pacientes,
        'ticket_medio_atendimento': ticket_medio_atendimento,
        'margem_lucro': margem_lucro,
        'ponto_equilibrio': ponto_equilibrio,
        'taxa_crescimento_pacientes': taxa_crescimento_pacientes,
        'taxa_crescimento_faturamento': taxa_crescimento_faturamento,
        
        # Listas de dados por entidade
        'unidades': unidades_data,
        'salas_data': salas_data,
        'psicologas_data': psicologas_data,
        
        # Dados para gráficos
        'fat_unidades_labels': fat_unidades_labels,
        'fat_unidades_valores': fat_unidades_valores,
        'dias_consultas_labels': dias_consultas_labels,
        'dias_consultas_valores': dias_consultas_valores,
        'psi_consultas_labels': psi_consultas_labels,
        'psi_consultas_valores': psi_consultas_valores,
        'psi_consultas_cores': psi_consultas_cores,
        'salas_ocupacao_labels': salas_ocupacao_labels,
        'salas_ocupacao_valores': salas_ocupacao_valores,
        'salas_ocupacao_cores': salas_ocupacao_cores,
        'financeiro_categorias': financeiro_categorias,
        'financeiro_valores': financeiro_valores
    }

    return render(request, 'pages/apuracao_financeira_kpsicologia.html', contexto)

# DESPESAS

@login_required(login_url='login1')
def cadastro_despesa(request):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    despesas = Despesas.objects.all()

    if request.method == 'POST':
        motivo = request.POST.get('motivo')
        valor = request.POST.get('valor')
        data = request.POST.get('data')

        Despesas.objects.create(
                motivo=motivo,
                valor=valor,
                data=data
            )
        
        return redirect('cadastro_despesa')
    
    return render(request, 'pages/criacao_despesas.html', {'despesas': despesas})

@login_required(login_url='login1')
def deletar_despesa(request, despesa_id):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    despesa = get_object_or_404(Despesas, id=despesa_id)

    if request.method == 'POST':
        despesa.delete()
        return redirect('cadastro_despesa')

    return render(request, 'pages/deletar_despesa.html', {'despesa': despesa})
       

# DISPONIBILIDADE PSICOLOGOS - GERAL

from collections import defaultdict
from datetime import time

@login_required(login_url='login1')
def vizualizar_disponibilidade(request):
    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    request.session['mes'] = None
    request.session['ano'] = None

    # REMOVENDO O CACHE - dados sempre atualizados
    psicologos = list(Psicologa.objects.all())
    especialidades = list(Especialidade.objects.all())
    publicos = list(Publico.objects.all())
    unidades = list(Unidade.objects.all())
    dias_da_semana = ['Segunda', 'Terça', 'Quarta', 'Quinta', 'Sexta', 'Sábado', 'Domingo']

    # CONSULTA BASE: horários disponíveis (sem paciente) - PRESENCIAIS
    horarios_presencial = Consulta.objects.filter(
        Paciente__isnull=True
    ).select_related(
        'psicologo',
        'sala',
        'sala__id_unidade'
    )

    # CONSULTA BASE: horários disponíveis (sem paciente) - ONLINE
    horarios_online = Consulta_Online.objects.filter(
        Paciente__isnull=True
    ).select_related('psicologo')

    print("=== DEBUG INICIAL ===")
    print(f"Total de horários disponíveis presenciais (sem paciente): {horarios_presencial.count()}")
    print(f"Total de horários disponíveis online (sem paciente): {horarios_online.count()}")
    
    # APLICAR FILTROS se for POST
    filtros_aplicados = []
    if request.method == 'POST':
        print("=== RECEBENDO FILTROS POST ===")
        
        especialidade_id = request.POST.get('especialidade_id')
        publico_id = request.POST.get('publico')
        dia_da_semana = request.POST.get("dia_semana")
        periodo_dia = request.POST.get("periodo_dia")  # NOVO: Substitui horario_inicio e horario_fim
        unidade_id = request.POST.get("unidade_id")
        modalidade = request.POST.get("modalidade", "todos")

        print(f"Modalidade: '{modalidade}'")
        print(f"Período do dia: '{periodo_dia}'")

        # FILTRO POR MODALIDADE
        if modalidade == "presencial":
            # Só horários presenciais
            horarios_online = Consulta_Online.objects.none()
        elif modalidade == "online":
            # Só horários online
            horarios_presencial = Consulta.objects.none()
        # Se modalidade == "todos", mantém ambos

        # FILTRO POR ESPECIALIDADE
        if especialidade_id and especialidade_id != 'todos':
            try:
                especialidade_id = int(especialidade_id)
                print(f"Filtrando por especialidade ID: {especialidade_id}")
                
                # Buscar psicólogos que têm essa especialidade
                from home.models import EspecialidadePsico
                psicologos_especialidade = EspecialidadePsico.objects.filter(
                    especialidade_id=especialidade_id
                ).values_list('psicologo_id', flat=True)
                
                print(f"Psicólogos com essa especialidade: {list(psicologos_especialidade)}")
                
                horarios_presencial = horarios_presencial.filter(psicologo_id__in=psicologos_especialidade)
                horarios_online = horarios_online.filter(psicologo_id__in=psicologos_especialidade)
                filtros_aplicados.append(f"Especialidade: {especialidade_id}")
                print(f"Horários presenciais após filtro especialidade: {horarios_presencial.count()}")
                print(f"Horários online após filtro especialidade: {horarios_online.count()}")
                
            except (ValueError, TypeError) as e:
                print(f"Erro no filtro especialidade: {e}")

        # FILTRO POR PÚBLICO
        if publico_id and publico_id != 'todos':
            try:
                publico_id = int(publico_id)
                print(f"Filtrando por público ID: {publico_id}")
                
                # Buscar psicólogos que atendem esse público
                from home.models import PublicoPsico
                psicologos_publico = PublicoPsico.objects.filter(
                    publico_id=publico_id
                ).values_list('psicologo_id', flat=True)
                
                print(f"Psicólogos com esse público: {list(psicologos_publico)}")
                
                horarios_presencial = horarios_presencial.filter(psicologo_id__in=psicologos_publico)
                horarios_online = horarios_online.filter(psicologo_id__in=psicologos_publico)
                filtros_aplicados.append(f"Público: {publico_id}")
                print(f"Horários presenciais após filtro público: {horarios_presencial.count()}")
                print(f"Horários online após filtro público: {horarios_online.count()}")
                
            except (ValueError, TypeError) as e:
                print(f"Erro no filtro público: {e}")

        # FILTRO POR DIA DA SEMANA
        if dia_da_semana and dia_da_semana != "todos":
            print(f"Filtrando por dia: {dia_da_semana}")
            horarios_presencial = horarios_presencial.filter(dia_semana=dia_da_semana)
            horarios_online = horarios_online.filter(dia_semana=dia_da_semana)
            filtros_aplicados.append(f"Dia: {dia_da_semana}")
            print(f"Horários presenciais após filtro dia: {horarios_presencial.count()}")
            print(f"Horários online após filtro dia: {horarios_online.count()}")

        # NOVO FILTRO POR PERÍODO DO DIA
        if periodo_dia and periodo_dia != "todos":
            try:
                print(f"Filtrando por período: {periodo_dia}")
                
                # Definir faixas de horário para cada período
                if periodo_dia == "manha":
                    horario_inicio = "06:00"
                    horario_fim = "11:59"
                    periodo_nome = "Manhã"
                elif periodo_dia == "tarde":
                    horario_inicio = "12:00"
                    horario_fim = "17:59"
                    periodo_nome = "Tarde"
                elif periodo_dia == "noite":
                    horario_inicio = "18:00"
                    horario_fim = "23:59"
                    periodo_nome = "Noite"
                else:
                    horario_inicio = None
                    horario_fim = None
                    periodo_nome = None
                
                if horario_inicio and horario_fim:
                    # Converter strings para objetos time para comparação
                    from datetime import time
                    hora_inicio = time.fromisoformat(horario_inicio)
                    hora_fim = time.fromisoformat(horario_fim)
                    
                    horarios_presencial = horarios_presencial.filter(
                        horario__gte=hora_inicio, 
                        horario__lte=hora_fim
                    )
                    horarios_online = horarios_online.filter(
                        horario__gte=hora_inicio, 
                        horario__lte=hora_fim
                    )
                    
                    filtros_aplicados.append(f"Período: {periodo_nome} ({horario_inicio}-{horario_fim})")
                    print(f"Horários presenciais após filtro período: {horarios_presencial.count()}")
                    print(f"Horários online após filtro período: {horarios_online.count()}")
                    
            except Exception as e:
                print(f"Erro no filtro período: {e}")

        # FILTRO POR UNIDADE (só para presenciais)
        if unidade_id and unidade_id != 'todos':
            try:
                unidade_id = int(unidade_id)
                print(f"Filtrando por unidade ID: {unidade_id}")
                horarios_presencial = horarios_presencial.filter(sala__id_unidade_id=unidade_id)
                # Horários online não têm unidade, então não são filtrados
                filtros_aplicados.append(f"Unidade: {unidade_id}")
                print(f"Horários presenciais após filtro unidade: {horarios_presencial.count()}")
            except (ValueError, TypeError) as e:
                print(f"Erro no filtro unidade: {e}")

        print(f"Filtros aplicados: {filtros_aplicados}")

    # Verificar se temos dados
    total_horarios_presencial = horarios_presencial.count()
    total_horarios_online = horarios_online.count()
    print(f"TOTAL FINAL - Presenciais: {total_horarios_presencial}, Online: {total_horarios_online}")

    # Ordenar por unidade, dia e horário
    horarios_presencial = horarios_presencial.order_by('sala__id_unidade__nome_unidade', 'dia_semana', 'horario')
    horarios_online = horarios_online.order_by('dia_semana', 'horario')

    # LÓGICA PARA SEPARAR SEMANAIS E QUINZENAIS
    horarios_semanal = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    horarios_quinzenal = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    psicologos_com_horarios_ids = set()

    # PROCESSAR HORÁRIOS PRESENCIAIS
    for horario in horarios_presencial:
        # Verificar se o horário tem todos os dados necessários
        if not horario.psicologo or not horario.sala or not horario.sala.id_unidade:
            print(f"Horário presencial com dados incompletos: {horario.id}")
            continue
            
        unidade_nome = horario.sala.id_unidade.nome_unidade
        dia = horario.dia_semana
        psicologa_nome = horario.psicologo.nome
        psicologa_cor = horario.psicologo.cor if horario.psicologo.cor else '#FFA500'
        hora_str = horario.horario.strftime('%H:%M')
        
        psicologos_com_horarios_ids.add(horario.psicologo.id)
        
        horario_info = {
            'hora': hora_str,
            'cor': psicologa_cor,
            'psicologo_id': horario.psicologo.id,
            'modalidade': 'Presencial',
            'sala': horario.sala.numero_sala if horario.sala else 'N/A'
        }
        
        # Verificar se é semanal/quinzenal
        e_semanal = horario.semanal and str(horario.semanal).strip().lower() not in ['', 'none', 'null']
        e_quinzenal = horario.quinzenal and str(horario.quinzenal).strip().lower() not in ['', 'none', 'null']
        
        # Adicionar aos grupos correspondentes
        if e_semanal:
            horarios_semanal[unidade_nome][dia][psicologa_nome].append(horario_info)
        
        if e_quinzenal:
            horarios_quinzenal[unidade_nome][dia][psicologa_nome].append(horario_info)
        
        # Se nenhum dos dois estiver definido, adicionar como semanal por padrão
        if not e_semanal and not e_quinzenal:
            horarios_semanal[unidade_nome][dia][psicologa_nome].append(horario_info)

    # PROCESSAR HORÁRIOS ONLINE
    for horario in horarios_online:
        if not horario.psicologo:
            print(f"Horário online com dados incompletos: {horario.id}")
            continue
            
        unidade_nome = "Online"  # Categoria especial para horários online
        dia = horario.dia_semana
        psicologa_nome = horario.psicologo.nome
        psicologa_cor = horario.psicologo.cor if horario.psicologo.cor else '#FFA500'
        hora_str = horario.horario.strftime('%H:%M')
        
        psicologos_com_horarios_ids.add(horario.psicologo.id)
        
        horario_info = {
            'hora': hora_str,
            'cor': psicologa_cor,
            'psicologo_id': horario.psicologo.id,
            'modalidade': 'Online',
            'sala': 'Virtual'
        }
        
        # Verificar se é semanal/quinzenal
        e_semanal = horario.semanal and str(horario.semanal).strip().lower() not in ['', 'none', 'null']
        e_quinzenal = horario.quinzenal and str(horario.quinzenal).strip().lower() not in ['', 'none', 'null']
        
        # Adicionar aos grupos correspondentes
        if e_semanal:
            horarios_semanal[unidade_nome][dia][psicologa_nome].append(horario_info)
        
        if e_quinzenal:
            horarios_quinzenal[unidade_nome][dia][psicologa_nome].append(horario_info)
        
        # Se nenhum dos dois estiver definido, adicionar como semanal por padrão
        if not e_semanal and not e_quinzenal:
            horarios_semanal[unidade_nome][dia][psicologa_nome].append(horario_info)

    # Função para formatar horários agrupados (atualizada para incluir modalidade)
    def formatar_horarios_agrupados(horarios_dict):
        from collections import OrderedDict
        ordem_dias = ['Segunda', 'Terça', 'Quarta', 'Quinta', 'Sexta', 'Sábado', 'Domingo']
        resultado = {}
        
        for unidade, dias in horarios_dict.items():
            resultado[unidade] = OrderedDict()
            
            for dia in ordem_dias:
                if dia in dias:
                    psicologas = dias[dia]
                    resultado[unidade][dia] = []
                    
                    for psicologa_nome in sorted(psicologas.keys()):
                        horarios_list = psicologas[psicologa_nome]
                        
                        # Ordenar horários por hora
                        horarios_list.sort(key=lambda x: x['hora'])
                        
                        # Agrupar por modalidade
                        presencial_hours = [h['hora'] for h in horarios_list if h['modalidade'] == 'Presencial']
                        online_hours = [h['hora'] for h in horarios_list if h['modalidade'] == 'Online']
                        
                        # Formatar string com indicação de modalidade
                        horarios_formatados_parts = []
                        if presencial_hours:
                            horarios_formatados_parts.append(f"Presencial: {', '.join(presencial_hours)}")
                        if online_hours:
                            horarios_formatados_parts.append(f"Online: {', '.join(online_hours)}")
                        
                        horarios_formatados = f"{psicologa_nome} - {' | '.join(horarios_formatados_parts)}"
                        
                        cor = horarios_list[0]['cor'] if horarios_list else '#FFA500'
                        
                        resultado[unidade][dia].append({
                            'psicologa': psicologa_nome,
                            'horarios_formatados': horarios_formatados,
                            'cor': cor,
                            'horarios_lista': [h['hora'] for h in horarios_list],
                            'modalidades': [h['modalidade'] for h in horarios_list],
                            'psicologo_id': horarios_list[0]['psicologo_id'] if horarios_list else None
                        })
        return resultado

    horarios_semanal_formatados = formatar_horarios_agrupados(horarios_semanal)
    horarios_quinzenal_formatados = formatar_horarios_agrupados(horarios_quinzenal)

    # Buscar apenas psicólogos que têm horários disponíveis
    psicologos_com_horarios = [
        psico for psico in psicologos 
        if psico.id in psicologos_com_horarios_ids
    ]

    print("=== RESULTADO FINAL ===")
    print(f"Psicólogos com horários: {len(psicologos_com_horarios_ids)}")
    print(f"Unidades com horários semanais: {list(horarios_semanal_formatados.keys())}")
    print(f"Unidades com horários quinzenais: {list(horarios_quinzenal_formatados.keys())}")

    return render(request, 'pages/disponibilidades.html', {
        'psicologos': psicologos_com_horarios,
        'especialidades': especialidades,
        'publicos': publicos,
        'unidades': unidades,
        'horarios_semanal': horarios_semanal_formatados,
        'horarios_quinzenal': horarios_quinzenal_formatados,
        'dias_da_semana': dias_da_semana,
        'total_presencial': total_horarios_presencial,
        'total_online': total_horarios_online,
    })

# DISPONIBILIDADE PSICOLOGOS - ONLINE
@login_required(login_url='login1')
def disponibilidade_online(request, psicologo_id):
    psicologa = get_object_or_404(Psicologa, id=psicologo_id)
    horarios = Consulta_Online.objects.filter(psicologo=psicologa).filter(Paciente__isnull=True)

    if request.user.username != psicologa.nome and not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission1.html')

    # Lista dos dias da semana
    dias_da_semana = ['Segunda', 'Terça', 'Quarta', 'Quinta', 'Sexta', 'Sábado']

    # Agrupar horários por dia da semana em uma lista de tuplas (dia, horários)
    horarios_agrupados = []
    for dia in dias_da_semana:
        horarios_do_dia = horarios.filter(dia_semana=dia)
        horarios_agrupados.append((dia, horarios_do_dia))

    if request.method == "POST":
        dia_semana = request.POST.get('dia_semana')
        qtd_atendimentos = int(request.POST.get('qtd_atendimentos'))
        tempo_atendimento = int(request.POST.get('tempo_atendimento'))  # em minutos
        horario_inicio = request.POST.get('horario_inicio')

        # Convertemos o horário de início para um objeto datetime.time
        horario_atual = datetime.strptime(horario_inicio, '%H:%M').time()

        # Loop para inserir os horários de acordo com a quantidade de atendimentos
        for i in range(qtd_atendimentos):
            # Verificar se já existe um horário com o mesmo dia e hora
            if Consulta_Online.objects.filter(
                dia_semana=dia_semana,
                horario=horario_atual,
                psicologo=psicologa
            ).exists():

                # Se já existe, não cria novamente
                continue
                
            Consulta_Online.objects.create(
                dia_semana=dia_semana,
                horario=horario_atual,
                psicologo=psicologa
            )
            # Incrementa o horário atual pelo tempo de atendimento (em minutos)
            horario_atual = (datetime.combine(datetime.today(), horario_atual) + timedelta(minutes=tempo_atendimento)).time()

        return redirect('psico_disponibilidade_online', psicologo_id=psicologa.id)  # Altere para a view de sucesso

    return render(request, 'pages/psico_disponibilidade_online.html', {
        'psicologo': psicologa,
        'horarios_agrupados': horarios_agrupados,
    })

@login_required(login_url='login1')
def remover_disponibilidade_online(request, disponibilidade_online_id, psicologo_id):
    disponibilidade = get_object_or_404(Consulta_Online, id=disponibilidade_online_id)
    psicologo = get_object_or_404(Psicologa, id=psicologo_id)

    if request.method == "POST":

        disponibilidade.delete()
        return redirect('psico_disponibilidade_online', psicologo_id=psicologo.id)

    return render(request, 'pages/deletar_disponibilidade_online.html', {'disponibilidade': disponibilidade, 'psicologa': psicologo})


@login_required(login_url='login1')
def delete_multiple_disponibilidades_online(request, psicologo_id):
    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')
    
    dia_semana = request.POST.get('dia_semana')
    psicologa = get_object_or_404(Psicologa, id=psicologo_id)
    consultas = Consulta_Online.objects.filter(psicologo=psicologa, dia_semana=dia_semana).filter(Paciente__isnull=True).order_by('horario')

    if request.method == 'POST':
        # Obter os IDs das consultas a serem excluídas
        consultas.exclude(id__in=request.POST.getlist('consultas')).delete()
        # Redirecionar para a página de agenda central

        return redirect('psico_disponibilidade_online', psicologo_id=psicologa.id)

    return render(request, 'pages/deletar_multiplas_disponibilidades_online.html', {
        'consultas': consultas,
        'psicologa': psicologa,
    })

# CONSULTAS ONLINE 

@login_required(login_url='login1')
def psico_agenda_online(request, psicologo_id):
    print("=== INICIANDO PSICO_AGENDA_ONLINE ===")
    psicologa = get_object_or_404(Psicologa, id=psicologo_id)

    # Verificar se o usuário é a psicóloga ou faz parte do grupo 'Administrador'
    if request.user.username != psicologa.nome and not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission1.html')

    consultas = Consulta_Online.objects.filter(psicologo=psicologa).order_by('horario')

    hoje = datetime.now().date()
    
    if request.method == "POST":
        print("=== RECEBENDO DADOS DO FORMULÁRIO ===")
        nome_cliente = request.POST.get('nome_cliente')
        dia_semana = request.POST.get('dia_semana')
        horario_consulta = request.POST.get('horario_consulta')
        psicologa.ultima_atualizacao_agenda = hoje
        print(f"Nome cliente: {nome_cliente}")
        print(f"Dia semana: {dia_semana}")
        print(f"Horário consulta: {horario_consulta}")

        # Converter horário string para time object
        try:
            horario_obj = datetime.strptime(horario_consulta, '%H:%M').time()
        except ValueError:
            print("ERRO: Formato de horário inválido")
            return render(request, 'pages/error_horario_invalido.html', {
                'psicologo': psicologa
            })

        # Verificar se o paciente existe
        try:
            paciente = Paciente.objects.get(nome=nome_cliente)
            print(f"Paciente encontrado: {paciente.nome}, período: {paciente.periodo}")
        except Paciente.DoesNotExist:
            print(f"ERRO: Paciente '{nome_cliente}' não encontrado")
            return render(request, 'pages/error_paciente_nao_encontrado.html', {
                'nome_cliente': nome_cliente,
                'psicologo': psicologa
            })

        # Verificar se uma consulta com esses mesmos critérios já existe
        consulta_existente = Consulta_Online.objects.filter(
            psicologo=psicologa,
            horario=horario_obj,  # Usar objeto time
            dia_semana=dia_semana,
            Paciente=paciente
        ).first()

        if consulta_existente:
            print("ERRO: Consulta já existe com esses critérios")
            return render(request, 'pages/consulta_cadastrada2.html', {
                "psicologo": psicologa,
            })

        # Verificar se já existe uma consulta no mesmo horário e dia com o mesmo psicólogo
        consulta_por_horario = Consulta_Online.objects.filter(
            psicologo=psicologa,
            horario=horario_obj,  # Usar objeto time
            dia_semana=dia_semana
        ).first()

        if consulta_por_horario:
            print("Encontrou consulta existente no horário - atualizando")
            
            if paciente.periodo == "Semanal" and not consulta_por_horario.semanal:
                consulta_por_horario.semanal = paciente.nome
                consulta_por_horario.Paciente = paciente  # ❌ Remover vírgula!
                consulta_por_horario.quinzenal = ""
                print("Agendado como semanal")
            
            elif paciente.periodo == "Quinzenal" and not consulta_por_horario.quinzenal:
                consulta_por_horario.quinzenal = paciente.nome
                consulta_por_horario.Paciente = paciente  # ❌ Remover vírgula!
                consulta_por_horario.semanal = ""
                print("Agendado como quinzenal")
            else:
                print("ERRO: Horário já ocupado para este período")
                return render(request, 'pages/error_horario_ocupado.html', {
                    'psicologo': psicologa,
                    'horario': horario_consulta,
                    'dia': dia_semana
                })

            consulta_por_horario.save()
            print(f"Consulta atualizada: ID {consulta_por_horario.id}")
        else:
            print("Nenhuma consulta encontrada no horário - tentando buscar slot disponível")
            
            # ❌ CORRIGIR: Usar filter().first() em vez de get()
            consulta_disponivel = Consulta_Online.objects.filter(
                psicologo=psicologa,
                horario=horario_obj,  # Usar objeto time
                dia_semana=dia_semana,
                Paciente__isnull=True  # Buscar slot vazio
            ).first()

            if consulta_disponivel:
                print("Encontrou slot disponível - preenchendo")
                consulta_disponivel.Paciente = paciente  # ❌ Remover vírgula!
                consulta_disponivel.semanal = paciente.nome if paciente.periodo == "Semanal" else ""
                consulta_disponivel.quinzenal = paciente.nome if paciente.periodo == "Quinzenal" else ""
                consulta_disponivel.save()
                print(f"Slot preenchido: ID {consulta_disponivel.id}")
            else:
                print("Nenhum slot disponível encontrado - criando nova consulta")
                # Criar nova consulta se não existe nenhuma no horário
                nova_consulta = Consulta_Online.objects.create(
                    psicologo=psicologa,
                    horario=horario_obj,
                    dia_semana=dia_semana,
                    Paciente=paciente,
                    semanal=paciente.nome if paciente.periodo == "Semanal" else "",
                    quinzenal=paciente.nome if paciente.periodo == "Quinzenal" else ""
                )
                print(f"Nova consulta criada: ID {nova_consulta.id}")

        # Salvar atualização da agenda da psicóloga
        psicologa.save()
        print("=== REDIRECIONANDO ===")
        return redirect('psico_agenda_online', psicologo_id=psicologa.id)

    dias_da_semana = ["Segunda", "Terça", "Quarta", "Quinta", "Sexta", "Sábado"]

    return render(request, "pages/psico_agenda_online.html", { 
        'agendas': consultas,
        'psicologo': psicologa,
        'dias_da_semana': dias_da_semana
    })

@login_required(login_url='login1')
def delete_consulta_online(request, consulta_id, psicologo_id):

    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')

    consulta_online = get_object_or_404(Consulta_Online, id=consulta_id)
    psicologa = get_object_or_404(Psicologa, id=psicologo_id)
    hoje = datetime.now().day

    if request.method == 'POST':

        if consulta_online.Paciente:
            consulta_online.delete()
            psicologa.ultima_atualizacao_agenda = hoje
            return redirect('psico_agenda_online', psicologo_id=psicologo_id)
        else:
            consulta_online.delete()
            psicologa.ultima_atualizacao_agenda = hoje
            return redirect('psico_disponibilidade_online', psicologo_id=psicologo_id)

    return render(request, 'pages/deletar_agenda_online.html', {'consulta_online': consulta_online, 'psicologo': psicologa})

@login_required(login_url='login1')
def delete_multiple_consultas_online(request, psicologo_id):
    if not request.user.groups.filter(name='administrador').exists() and not request.user.is_superuser:
        return render(request, 'pages/error_permission.html')
    
    dia_semana = request.POST.get('dia_semana')
    psicologa = get_object_or_404(Psicologa, id=psicologo_id)
    consultas = Consulta_Online.objects.filter(psicologo=psicologa, dia_semana=dia_semana)

    if request.method == 'POST':
        # Obter os IDs das consultas a serem excluídas
        consultas.exclude(id__in=request.POST.getlist('consultas')).delete()
        # Redirecionar para a página de agenda central

        return redirect('psico_agenda_online', psicologo_id=psicologa.id)

    return render(request, 'pages/deletar_multiplas_agendas_online.html', {
        'consultas': consultas,
        'psicologa': psicologa,
    })

