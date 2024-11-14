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
    path('cadastrar_salas/', views.cadastrar_sala, name='cadastrar_salas'),
    path('unidades_atendimento/', views.unis, name='unidade_atendimento'),
    path("users/<int:user_id>/delete/", views.delete_user, name="delete_user"),
    path("users/<int:user_id>/update/", views.update_user, name="update_user"),
    path("unidades_atendimento/<int:unidade_id>/update/", views.update_uni, name="update_unidade"),
    path("unidades_atendimento/<int:unidade_id>/delete/", views.delete_uni, name="delete_unidade"),
    path("cadastrar_salas/<int:id_sala>/update/", views.update_sala, name="update_sala"),
    path("cadastrar_salas/<int:id_sala>/delete/", views.delete_sala, name="delete_sala"),

    path('perfil_usuario/', views.perfil, name='perfil_usuario'),
    path('perfil_usuario/<int:user_id>/editar_perfil/', views.update_profile, name='editar_perfil'),   
    path('agenda_central/', views.create_consulta, name='agenda_central'),
    #path('perfil_usuario/<int:user_id>/editar_perfil/', views.update_profile, name='editar_perfil'),
    path('psicologas/', views.psicologa, name='psicologa'),
    # URLs para gerenciamento de consultas
    path('consultas/', views.create_consulta, name='lista_consultas'),  # URL para listar consultas
    #path('consultas/novo/', views.create_consulta, name='create_consulta'),  # URL para criar nova consulta
    path('consultas/editar/<int:id_consulta>/', views.update_consulta, name='update_consulta'),  # URL para editar consulta
    path('consultas/deletar/<int:id_consulta>/', views.delete_consulta, name='delete_consulta'),  # URL para deletar consulta
    path('pacientes/', views.pacientes, name='pacientes'),
    path('pacientes/<int:id_paciente>/editar', views.editar_paciente, name='update_paciente'),
    path('pacientes/<int:id_paciente>/deletar', views.deletar_paciente, name='delete_paciente'),
    path('psicologas/editar/<int:id_consulta>/', views.editar_confirma_consulta, name='editar_confirma_consulta'),  # URL para confirmar consulta  # URL para confirmar consulta
    path('deletar_psicologo/<int:psicologo_id>/delete/', views.deletar_psicologo, name='deletar_psicologo'),
    path('editar_psicologo/<int:psicologo_id>/editar/', views.editar_psicologo, name='editar_psicologo'),
    path('psicologas/<int:psicologo_id>/confirmar/', views.confirma_consulta, name='confirma_consulta'),
    path('psicologas/<int:psicologo_id>/confirmar/<int:consulta_id>/excluir', views.deletar_consulta, name='deletar_consulta'),
    path('psicologas/<int:psicologo_id>/confirmar/<int:consulta_id>/editar', views.editar_confirma_consulta, name='editar_confirma_consulta'),
    path('psicologas/<int:psicologo_id>/agendar/', views.psico_agenda, name='psico_agenda'),
    path('deletar_agenda_psico/<int:id_psicologo>/<int:id_horario>', views.deletar_psico_agenda, name='delete_psico_agenda'),
    path('agenda_central/sala/<int:id_sala>', views.agenda_central_sala, name='agenda_central_sala'),
    path('financeiro/', views.financeiro, name='financeiro'),
    path('geracao_recibo/<int:id_consulta>', views.gerar_recibo, name='gerar_recibo'),

    #path('cadastrar_salas/', views.sala, name='salas'),

    #path('agenda_central/<int:user_id>/editar_agenda_central/'),
    #path('agenda_central/', lista_consultas, name='lista_consultas'),  # URL para listar consultas
    #path('consultas/novo/', create_consulta, name='create_consulta'),  # URL para criar nova consulta
    #path('consultas/editar/<int:consulta_id>/', update_consulta, name='update_consulta'),  # URL para editar consulta
    #path('consultas/deletar/<int:consulta_id>/', delete_consulta, name='delete_consulta'),  # URL para deletar consulta
]
