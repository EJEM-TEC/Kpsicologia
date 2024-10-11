from django.shortcuts import render, redirect
from django.contrib.auth.views import LoginView, PasswordResetView, PasswordChangeView, PasswordResetConfirmView
from home.forms import RegistrationForm, LoginForm, UserPasswordResetForm, UserSetPasswordForm, UserPasswordChangeForm
from django.contrib.auth import logout
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import Usuario
# from .models import User
# Create your views here.

# Pages
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


#def users(request):
#  return render(request, 'pages/page_user.html', {'segment': 'user'})


# Authentication
class UserLoginView(LoginView):
  template_name = 'accounts/login.html'
  form_class = LoginForm

def register(request):
  if request.method == 'POST':
    form = RegistrationForm(request.POST)
    if form.is_valid():
      form.save()
      print('Account created successfully!')
      return redirect('/accounts/login/')
    else:
      print("Register failed!")
  else:
    form = RegistrationForm()

  context = { 'form': form }
  return render(request, 'accounts/register.html', context)

def logout_view(request):
  logout(request)
  return redirect('/accounts/login/')

class UserPasswordResetView(PasswordResetView):
  template_name = 'accounts/password_reset.html'
  form_class = UserPasswordResetForm

class UserPasswordResetConfirmView(PasswordResetConfirmView):
  template_name = 'accounts/password_reset_confirm.html'
  form_class = UserSetPasswordForm

class UserPasswordChangeView(PasswordChangeView):
  template_name = 'accounts/password_change.html'
  form_class = UserPasswordChangeForm

# e aqui
#@login_required -> tirar o comando depois que o login estiver pronto
def lista_usuarios(request):
  users = users.objects.all()
  return render(request, 'users/page_user.html', {'usuarios': users})

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
