from django.shortcuts import render, redirect
from django.contrib.auth.views import LoginView, PasswordResetView, PasswordChangeView, PasswordResetConfirmView
from home.forms import RegistrationForm, LoginForm, UserPasswordResetForm, UserSetPasswordForm, UserPasswordChangeForm
from django.contrib.auth import logout, authenticate, login as auth_login
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User, Group
from django.http import HttpResponse
from .models import Usuario

# Páginas Simples
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
class UserLoginView(LoginView):
    template_name = 'accounts/login.html'
    form_class = LoginForm

    # Redireciona o usuário com base no tipo (administrador ou comum)
    def form_valid(self, form):
        auth_login(self.request, form.get_user())
        if is_admin(self.request.user):
            return redirect('/admin_dashboard/')  # Redireciona administradores para o painel administrativo
        else:
            return redirect('/profile/')  # Redireciona usuários comuns para a página de perfil

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
@login_required(login_url='/accounts/login/')
def logout_view(request):
    logout(request)
    return redirect('/accounts/login/')

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

# Função para cadastrar ou listar usuários
@login_required(login_url='/accounts/login/')
@user_passes_test(is_admin)

def users(request):
    novo_user = Usuario()
    
    if request.method == 'POST':
        username = request.POST.get('username')
        idade = request.POST.get('idade')
        email = request.POST.get('email')
        cargo = request.POST.get('cargo')
        telefone = request.POST.get('telefone')  # Verifique se isso está no seu formulário HTML
        rg = request.POST.get('rg')
        
        # Verificação dos campos obrigatórios
        if not username or not email or not idade or not telefone:
            return render(request, 'pages/page_user.html', {
                'error': 'Por favor, preencha todos os campos obrigatórios!',
                'users': Usuario.objects.all()
            })
        
        try:
            novo_user.username = username
            novo_user.idade = int(idade)
            novo_user.email = email
            novo_user.cargo = cargo
            novo_user.telefone = telefone
            novo_user.rg = rg
            novo_user.save()
            
            return redirect('users')
        except ValueError:
            return render(request, 'pages/page_user.html', {
                'error': 'Idade deve ser um número!',
                'users': Usuario.objects.all()
            })
    
    users = Usuario.objects.all()
    
    return render(request, 'pages/page_user.html', {'users': users})
