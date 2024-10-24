"""core URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path
from home import views

urlpatterns = [
    #path('', include('home.urls')),
    path("admin/", admin.site.urls),
    #path("", include('admin_soft.urls'))
    path('', views.login, name='login1'),
    path('index/', views.index, name='index'),
    path('billing/', views.billing, name='billing'),
    path('tables/', views.tables, name='tables'),
    path('vr/', views.vr, name='vr'),
    path('rtl/', views.rtl, name='rtl'),
    path('profile/', views.profile, name='profile'),
    path('users/', views.users, name='users'),
    path('logout/', views.logout_user, name="logout"),
    path('login/', views.login, name='login'),
    path('salas/', views.sala, name='salas'),
    path('unidades_atendimento/', views.unis, name='unidade_atendimento'),
    path("users/<int:user_id>/delete/", views.delete_user, name="delete_user"),
    path("users/<int:user_id>/update/", views.update_user, name="update_user"),
    path("unidades_atendimento/<int:unidade_id>/update/", views.update_uni, name="update_unidade"),
    path("unidades_atendimento/<int:unidade_id>/delete/", views.delete_uni, name="delete_unidade"),
    path("salas/<int:id_sala>/update/", views.update_sala, name="update_sala"),
    path("salas/<int:id_sala>/delete/", views.delete_sala, name="delete_sala"),
    path('perfil_usuario/', views.perfil, name='perfil_usuario'),
    path('perfil_usuario/<int:user_id>/editar_perfil/', views.update_profile, name='editar_perfil'),
    path('psicologa/', views.psicologa, name='psicologa'),   
]
