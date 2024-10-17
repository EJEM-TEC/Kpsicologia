from django.shortcuts import get_object_or_404, render, redirect
from django.contrib.auth.views import PasswordResetView, PasswordChangeView, PasswordResetConfirmView
from home.forms import RegistrationForm, UserPasswordResetForm, UserSetPasswordForm, UserPasswordChangeForm
from django.contrib.auth import logout, authenticate, login as login_django
from django.contrib.auth.decorators import login_required, user_passes_test
from rolepermissions.roles import assign_role
from rolepermissions.decorators import has_role_decorator
from django.contrib.auth.models import User, Group
from django.http import HttpResponse
from .models import Usuario, Unidade
from rolepermissions.roles import assign_role
from rolepermissions.exceptions import RoleDoesNotExist
from django.contrib.auth.models import Group
from django.contrib.auth import authenticate, login as login_django
from django.urls import reverse

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

# Função para verificar se o usuário é administrador
def is_admin(user):
    return user.groups.filter(name='administrador').exists()

# Função para verificar se o usuário é usuário comum
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
@login_required(login_url='/accounts/login/')
@user_passes_test(is_admin)
def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            group_name = request.POST.get('group')  # Define o tipo de usuário (administrador ou usuário comum)
            group, created = Group.objects.get_or_create(name=group_name)
            user.groups.add(group)
            print('Conta criada com sucesso!')
            return redirect('/accounts/login/')
        else:
            print("Falha no cadastro!")
    else:
        form = RegistrationForm()

    context = { 'form': form }
    return render(request, 'accounts/register.html', context)

# Logout
# @login_required(login_url='/accounts/login/')
# def logout_view(request):
#     logout(request)
#     return redirect('/accounts/login/')

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

# Listagem de usuários (somente administradores podem acessar)
@login_required(login_url='/accounts/login/')
@user_passes_test(is_admin)
def lista_usuarios(request):
    users = Usuario.objects.all()
    return render(request, 'users/page_user.html', {'usuarios': users})

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
        return render(request, 'accounts/login1.html')
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
        idade = request.POST.get('idade')
        cargo = request.POST.get('cargo')
        telefone = request.POST.get('telefone')
        rg = request.POST.get('rg')

        if username and idade and cargo and telefone and rg:
            user.username = username
            user.idade = idade
            user.cargo = cargo
            user.telefone = telefone
            user.rg = rg
            user.save()
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

# Listagem de unidades (somente administradores podem acessar)
@login_required(login_url='/accounts/login/')
@user_passes_test(is_admin)
def lista_unidades(request):
    unis = Unidade.objects.all()
    return render(request, 'unis/page_unidades.html', {'unidades': unis})

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

# def logout_user(request):
#         logout(request)
#         return redirect('login1')  # Redireciona para a página de login ou outra página de sua escolha

@login_required(login_url='login1')
def logout_user(request):
    # Realiza o logout do usuário
    logout(request)
    # Redireciona para a página de login após o logout
    return redirect(reverse('login1'))