from django.shortcuts import get_object_or_404, render, redirect
from django.contrib.auth.views import PasswordResetView, PasswordChangeView, PasswordResetConfirmView
from django.urls import reverse
from home.forms import RegistrationForm, UserPasswordResetForm, UserSetPasswordForm, UserPasswordChangeForm
from django.contrib.auth import logout, authenticate, login as login_django
from django.contrib.auth.decorators import login_required, user_passes_test
from rolepermissions.roles import assign_role
from rolepermissions.decorators import has_role_decorator
from django.contrib.auth.models import User, Group
from django.http import HttpResponse
from .models import Psicologa, Usuario, Consulta, Unidade, Sala, Paciente, ConfirmacaoConsulta, Psicologo, Disponibilidade, AgendaPsico, PsicoDisponibilidade
from rolepermissions.roles import assign_role, get_user_roles, RolesManager
from rolepermissions.exceptions import RoleDoesNotExist
from django.contrib.auth.models import Group
from django.contrib.auth import authenticate, login as login_django
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash
from datetime import timedelta
from django.db.models import Sum
from django.shortcuts import render, get_object_or_404, redirect

# Páginas Simples
@login_required(login_url='login1')
def index(request):
    return render(request, 'pages/index.html', { 'segment': 'index' })

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

# Login com redirecionamento baseado no tipo de usuário
# class UserLoginView(LoginView):
#     template_name = 'accounts/login.html'
#     form_class = LoginForm

#     # Redireciona o usuário com base no tipo (administrador ou comum)
#     def form_valid(self, form):
#         auth_login(self.request, form.get_user())
#         if is_admin(self.request.user):
#             return redirect('/admin_dashboard/')  # Redireciona administradores para o painel administrativo
#         else:
#             return redirect('/profile/')  # Redireciona usuários comuns para a página de perfil

# Registro de usuário (somente administradores podem cadastrar novos usuários)
# s

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

# # Listagem de usuários (somente administradores podem acessar)
# @login_required(login_url='/accounts/login/')
# @user_passes_test(is_admin)
# def lista_usuarios(request):
#     users = Usuario.objects.all()
#     return render(request, 'users/page_user.html', {'usuarios': users})

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
            return HttpResponse("Já existe um usuário com esse nome")

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
        return HttpResponse("Usuário ou senha inválidos")
    
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

def criar_atendimento(request):
    pass

# # Listagem de unidades (somente administradores podem acessar)
# @login_required(login_url='/accounts/login/')
# @user_passes_test(is_admin)
# def lista_unidades(request):
#     unis = Unidade.objects.all()
#     return render(request, 'unis/page_unidades.html', {'unidades': unis})

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
                return HttpResponse("Já existe uma unidade com esse nome")
            
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
    # if request.method == 'POST':
    #     username = request.POST.get('username')
    #     email = request.POST.get('email')
    #     cargo = request.POST.get('cargo')


# @login_required
# def editar_perfil(request, user_id):
#     user = get_object_or_404(User, id=user_id)
#     if request.method == 'POST':
#         form = EditProfileForm(request.POST)
#         if form.is_valid():
#             username = form.cleaned_data['username']
#             email = form.cleaned_data['email']
#             new_password = form.cleaned_data['new_password']

#             request.user.name = username
#             request.user.email = email

#             if new_password:
#                 request.user.set_password(new_password)

#             request.user.save()
#             return redirect('perfil_usuario')  # Redirecionar para a página de perfil
#     else:
#         form = EditProfileForm(initial={'name': request.user.name, 'email': request.user.email})

#     return render(request, 'pages/editar_perfil.html', {'form': form})


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

@login_required(login_url='login1')
@has_role_decorator('administrador')
def lista_consultas(request):
    consultas = Consulta.objects.all()
    return render(request, 'pages/page_agenda_central.html', {'consultas': consultas})

@login_required(login_url='login1')
@has_role_decorator('administrador')
def create_consulta(request):
    salas_atendimento = Sala.objects.all()
    consultas = Consulta.objects.all()
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
            return HttpResponse("Essa consulta já está cadastrada")

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

        return redirect('lista_consultas')
    
    return render(request, "pages/page_agenda_central.html", {
        'salas': salas_atendimento, 
        'psicologas': psicologas, 
        'pacientes': pacientes, 
        'consultas': consultas
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

            return HttpResponse("Essa consulta já está cadastrada")

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

        return redirect('lista_consultas')
    
    return render(request, "pages/edit_consulta.html", {
        'salas': salas_atendimento, 
        'psicologas': psicologas, 
        'pacientes': pacientes, 
        'consulta': consulta
    })

def page_agenda_central():
    return render('pages/editar_agenda_central.html')


@login_required(login_url='login1')
def delete_consulta(request, id_consulta):
    consulta = get_object_or_404(Consulta, id=id_consulta)

    if request.method == 'POST':
        consulta.delete()
        return redirect('lista_consultas')

    return render(request, 'pages/deletar_agenda_central.html', {'consulta': consulta})


def psicologa(request):
    
    psicologos = Psicologa.objects.all()

    if request.method == 'POST':
        nome = request.POST.get('nome')
        cor = request.POST.get('cor')
        email = request.POST.get('email')
        senha = request.POST.get('senha')

        psicologa = Psicologa.objects.create(
            nome = nome,
            cor = cor,
            email = email,
            senha = senha
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

    return render(request, 'pages/psicologa.html', {'psicologos': psicologos})

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
        'consulta_confirma': consulta_confirmadas,
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
        rg_paciente = request.POST.get('rg_paciente')
        email_paciente = request.POST.get('email_paciente')
        telefone_paciente = request.POST.get('telefone_paciente')
        cpf_paciente = request.POST.get('cpf_paciente')
        periodo_paciente = request.POST.get('periodo_paciente')


        paciente = Paciente.objects.create(
            nome = nome_paciente,
            idade = idade_paciente,
            rg = rg_paciente,
            email = email_paciente,
            telefone = telefone_paciente,
            cpf = cpf_paciente,
            periodo = periodo_paciente
        )

        paciente.save()

        redirect('pacientes')
    
    return render(request, 'pages/pacientes.html', {'pacientes': pacientes})

@login_required(login_url='login1')
@has_role_decorator('administrador')
def editar_paciente(request, id_paciente):

    paciente = get_object_or_404(Paciente, id=id_paciente)

    if request.method == 'POST':
        nome_paciente = request.POST.get('nome_paciente')
        idade_paciente = request.POST.get('idade_paciente')
        rg_paciente = request.POST.get('rg_paciente')
        email_paciente = request.POST.get('email_paciente')
        telefone_paciente = request.POST.get('telefone_paciente')
        cpf_paciente = request.POST.get('cpf_paciente')
        periodo_paciente = request.POST.get('periodo_paciente')

        paciente.nome = nome_paciente;
        paciente.rg = rg_paciente;
        paciente.idade = idade_paciente;
        paciente.email = email_paciente;
        paciente.telefone = telefone_paciente;
        paciente.cpf = cpf_paciente;
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

def agenda_psicologo(request, id_psicologo):
    pass

def deletar_consulta(request, psicologo_id, consulta_id):
    consulta = get_object_or_404(ConfirmacaoConsulta, id=consulta_id)
    psicologo = get_object_or_404(Psicologo, id=psicologo_id)
    
    if request.method == "POST":
        consulta.delete()
        return redirect('confirma_consulta', psicologo_id=psicologo_id)
    
    return render(request, 'pages/confirmar_excluir_consulta.html', {
        'psicologo': psicologo,
        'consulta': consulta
    })



def editar_confirma_consulta(request, psicologo_id, consulta_id):
    psicologo = get_object_or_404(Psicologo, id=psicologo_id)
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


@login_required(login_url='login1') 
def psico_agenda(request, psicologo_id):
    psicologo = get_object_or_404(Psicologa, id=psicologo_id)
    psico_agendas = PsicoDisponibilidade.objects.filter(user_id=psicologo_id).select_related('disponibilidade')

    agenda = [ps.disponibilidade for ps in psico_agendas]

    if request.method == 'POST':
        dia_semana = request.POST.get('dia_semana')
        hora = request.POST.get('hora')

        if dia_semana and hora:
            # Cria a nova agenda
            nova_agenda = AgendaPsico.objects.create(
                dia_semana=dia_semana,
                hora=hora,
                livre_ocupado='Livre'
            )

            print(f"Psicologo ID: {psicologo.id}, Nova Agenda ID: {nova_agenda.id}")

            # Verifica se nova_agenda foi criada antes de associá-la
            if nova_agenda:
                PsicoDisponibilidade.objects.create(
                    user=psicologo,  # Aqui usamos o objeto `psicologo` diretamente
                    disponibilidade=nova_agenda  # Usamos `nova_agenda` diretamente
                )

            return redirect('psico_agenda', psicologo.id )

    return render(request, 'pages/psico_agenda.html', {
        'agendas': agenda,
        'psicologo': psicologo
    })


@login_required(login_url='login1')
def deletar_psico_agenda(request, id_psicologo, id_horario):
    
    psicologo = get_object_or_404(Psicologa, id=id_psicologo)

    horario = get_object_or_404(AgendaPsico, id=id_horario)

    psico_horario = get_object_or_404(PsicoDisponibilidade, disponibilidade=horario, user=psicologo.id)


    if request.method == "POST":

        psico_horario.delete()

        horario.delete()

        return redirect('psico_agenda', psicologo_id=psicologo.id)

    return render(request, 'pages/deletar_agenda.html', {'horario': horario})


def financeiro(request):
    return render(request, 'pages/financeiro.html')


@login_required(login_url='login_1')
def agenda_central_sala(request, id_sala):
    sala = get_object_or_404(Sala, id_sala = id_sala)

    agendas = Consulta.objects.filter(sala_id=sala)

    return render(request, 'pages/page_agenda_central_individual.html', {
        'agendas': agendas
    })
