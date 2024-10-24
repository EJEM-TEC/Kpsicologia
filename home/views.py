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
from .models import Usuario, Consulta, Unidade, Sala
from rolepermissions.roles import assign_role, get_user_roles, RolesManager
from rolepermissions.exceptions import RoleDoesNotExist
from django.contrib.auth.models import Group
from django.contrib.auth import authenticate, login as login_django
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash

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
def sala(request):
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
            return redirect('salas')  # Redirecionar após a criação
        except Exception as e:
            print(f"Erro ao criar sala: {e}")

    return render(request, 'pages/salas.html', {'salas': salas, 'unidades': unidades})



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
            return redirect("salas")
        else:
            return render(request, "pages/editar_sala.html", {'sala': sala, 'error': 'Preencha todos os campos.'})

    return render(request, "pages/editar_sala.html", {'sala': sala, 'unidades': unidades})


@login_required(login_url='login1')
def delete_sala(request, id_sala):
    sala= get_object_or_404(Sala, id_sala=id_sala)

    if request.method == 'POST':
        sala.delete()
        return redirect("salas")

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

        try:
            # Verifique se o usuário já existe
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

            # Tenta atribuir um role
            try:
                assign_role(user, cargo)
            except RoleDoesNotExist:
                return HttpResponse(f"O cargo {cargo} não existe. Verifique os cargos disponíveis.")

            return redirect('users')

        except ValueError:
            return render(request, 'pages/page_user.html', {
                'error': 'Idade deve ser um número!',
                'users': User.objects.all()
            })
    
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
        else:
            return render(request, "pages/editar_unidade.html", {'unidade': unidade, 'error': 'Preencha todos os campos.'})

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

@login_required
def editar_perfil(request, user_id):
    user= get_object_or_404(User, id=user_id)
    if request.method == 'POST':
        form = EditProfileForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            new_password = form.cleaned_data['new_password']

            request.user.name = username
            request.user.email = email

            if new_password:
                request.user.set_password(new_password)

            request.user.save()
            return redirect('perfil_usuario')  # Redirecionar para a página de perfil
    else:
        form = EditProfileForm(initial={'name': request.user.name, 'email': request.user.email})

    return render(request, 'pages/editar_perfil.html', {'form': form})


@login_required(login_url='login1')
def update_profile(request, user_id):
    user = get_object_or_404(User, id=user_id)
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        senha = request.POST.get('password')
        
        if username and email and senha:
            
            user.username = username
            user.email = email
            user.senha = senha

            user.save()

            return redirect("users")
        else:
            return render(request, "pages/editar_perfil.html", {'user': user, 'error': 'Preencha todos os campos.'})

    return render(request, "pages/editar_perfil.html", {'user': user})



@login_required(login_url='login1')
@has_role_decorator('administrador')
def lista_consultas(request):
    consultas = Consulta.objects.all()
    return render(request, 'pages/page_agenda_central.html', {'consultas': consultas})

@login_required(login_url='login1')
@has_role_decorator('administrador')
def create_consulta(request):
    if request.method == 'POST':
        numero_consulta = request.POST.get('numero_consulta')
        nome_cliente = request.POST.get('nome_cliente')
        nome_psicologo = request.POST.get('nome_psicologo')
        data_consulta = request.POST.get('data_consulta')
        horario_consulta = request.POST.get('horario_consulta')
        sala_atendimento = request.POST.get('sala_atendimento')
        unidade_atendimento = request.POST.get('unidade_atendimento')

        # Verifica se a consulta já existe
        consulta_existente = Consulta.objects.filter(numero_consulta=numero_consulta).first()
        if consulta_existente:
            return HttpResponse("Já existe uma consulta com esse número")

        # Criando uma nova consulta
        consulta = Consulta.objects.create(
            numero_consulta=numero_consulta,
            nome_cliente=nome_cliente,
            nome_psicologo=nome_psicologo,
            data_consulta=data_consulta,
            horario_consulta=horario_consulta,
            sala_atendimento=sala_atendimento,
            unidade_atendimento_id=unidade_atendimento
        )
        consulta.save()

    return redirect('lista_consultas')

@login_required(login_url='login1')
def update_consulta(request, consulta_id):
    consulta = get_object_or_404(Consulta, id_consulta=consulta_id)

    if request.method == 'POST':
        numero_consulta = request.POST.get('numero_consulta')
        nome_cliente = request.POST.get('nome_cliente')
        nome_psicologo = request.POST.get('nome_psicologo')
        data_consulta = request.POST.get('data_consulta')
        horario_consulta = request.POST.get('horario_consulta')
        sala_atendimento = request.POST.get('sala_atendimento')
        unidade_atendimento = request.POST.get('unidade_atendimento')

        # Atualiza os campos da consulta
        consulta.numero_consulta = numero_consulta
        consulta.nome_cliente = nome_cliente
        consulta.nome_psicologo = nome_psicologo
        consulta.data_consulta = data_consulta
        consulta.horario_consulta = horario_consulta
        consulta.sala_atendimento = sala_atendimento
        consulta.unidade_atendimento_id = unidade_atendimento
        consulta.save()

        return redirect('lista_consultas')
    
    return render(request, 'pages/editar_consulta.html', {'consulta': consulta})

@login_required(login_url='login1')
def delete_consulta(request, consulta_id):
    consulta = get_object_or_404(Consulta, id_consulta=consulta_id)

    if request.method == 'POST':
        consulta.delete()
        return redirect('lista_consultas')

    return render(request, 'pages/deletar_consulta.html', {'consulta': consulta})
