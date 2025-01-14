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
# from django.conf.urls import handler404, handler500



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
    #path('perfil_usuario/<int:user_id>/editar_perfil/', views.update_profile, name='editar_perfil'),
    path('psicologas/', views.psicologa, name='psicologa'),
    path('cadastros', views.cadastros, name='cadastros'),
    path('visualizar_psicologas', views.visualizar_psicologos, name='visualizar_psicologas'),
    # URLs para gerenciamento de consultas
    #path('consultas/novo/', views.create_consulta, name='create_consulta'),  # URL para criar nova consulta
    path('consultas/editar/<int:id_consulta>/', views.update_consulta, name='update_consulta'),  # URL para editar consulta
    path('consultas/deletar/<int:id_consulta>/', views.delete_consulta, name='delete_consulta'),  # URL para deletar consulta
    path('pacientes/', views.pacientes, name='pacientes'),
    path('pacientes/<int:id_paciente>/editar', views.editar_paciente, name='update_paciente'),
    path('pacientes/<int:id_paciente>/deletar', views.deletar_paciente, name='delete_paciente'),
    path('psicologas/editar/<int:id_consulta>/', views.editar_confirma_consulta, name='editar_confirma_consulta'),  # URL para confirmar consulta  # URL para confirmar consulta
    path('deletar_psicologo/<int:psicologo_id>/delete/', views.deletar_psicologo, name='deletar_psicologo'),
    path('editar_psicologo/<int:psicologo_id>/editar/', views.editar_psicologo, name='editar_psicologo'),
    path('psicologas/<int:psicologo_id>/confirmar/', views.Confirmar_Consulta, name='confirma_consulta'),
    path('psicologas/<int:psicologo_id>/adicionar/', views.AdicionarConfirma_consulta, name='adiciona_confirma_consulta'),
    path('psicologas/<int:psicologo_id>/confirmar/<int:consulta_id>/excluir', views.deletar_consulta, name='deletar_consulta'),
    path('psicologas/<int:financeiro_id>/editar', views.EditarConfirmaConsulta, name='editar_confirma_consulta'),
    path('psicologas/<int:psicologo_id>/excluir', views.ExcluirConfirma_consulta, name='deletar_confirma_consulta'),
    path('psicologas/<int:psicologo_id>/agendar/', views.psico_agenda, name='psico_agenda'),
    path('psicologas/<int:psicologo_id>/disponibilidade/', views.definir_disponibilidade, name='psico_disponibilidade'),
    path('financeiro/', views.financeiro, name='financeiro'),
    path('editar_financeiro/<int:id_financeiro>', views.editar_financeiro, name='editar_financeiro'),
    path('agenda_central', views.agenda_central, name='agenda_central'),
    path('especialidades', views.cadastrar_especialidade, name='especialidades'),
    path('publicos', views.cadastrar_publico, name='publicos'),
    path('deletar_publico/<int:publico_id>', views.deletar_publico, name='deletar_publico'),
    path('psicologo_especialidade/<int:psicologo_id>', views.AssociarPsicoEspecialidade, name='psicoEspecialidades'),
    path('psicologo_especialidade/<int:psicologo_id>/<int:especialidade_id>', views.DissociarPsicoEspecialidade, name='disPsicoEspecialidade'),
    path('psicologo_publico/<int:psicologo_id>', views.AssociarPsicoPublico, name='psicoPublicos'),
    path('psicologo_publico/<int:psicologo_id>/<int:publico_id>', views.DissociarPsicoPublico, name='disPsicoPublico'),
    path('psicologo_unidade/<int:psicologo_id>', views.AssociarPsicoUnidade, name='psicoUnidades'),
    path('psicologo_unidade/<int:psicologo_id>/<int:unidade_id>', views.DissociarPsicoUnidade, name='disPsicoUnidade'),
    path('consultar_financeiro', views.consultar_financeiro, name='consultar_financeiro'),
    path('handler404/', views.handler404, name='handler404'),
    path('consulta_cadastrada1/', views.consulta_cadastrada1, name='consulta_cadastrada1'),
    path('consulta_cadastrada2/', views.consulta_cadastrada2, name='consulta_cadastrada2'),
    path('nome_usuario_erro/', views.nome_usuario_erro, name='nome_usuario_erro'),
    path('login_erro/', views.login_erro, name='login_erro'),
    path('unis_erro/', views.unis_erro, name='unis_erro'),
    path('consultar_disponibilidade', views.vizualizar_disponibilidade, name='consultar_disponibilidade'),
    path('deletar_disponibilidade/<int:disponibilidade_id>/<int:psicologo_id>', views.remover_disponibilidade, name='deletar_disponibilidade'),
    path('editar_consultas/<int:psicologo_id>', views.editar_consultas, name='editar_consultas'),


    #path('cadastrar_salas/', views.sala, name='salas'),

    #path('agenda_central/<int:user_id>/editar_agenda_central/'),
    #path('agenda_central/', lista_consultas, name='lista_consultas'),  # URL para listar consultas
    #path('consultas/novo/', create_consulta, name='create_consulta'),  # URL para criar nova consulta
    #path('consultas/editar/<int:consulta_id>/', update_consulta, name='update_consulta'),  # URL para editar consulta
    #path('consultas/deletar/<int:consulta_id>/', delete_consulta, name='delete_consulta'),  # URL para deletar consulta
]
# handler404 = 'home.views.handler404'
# handler500 = 'home.views.handler500'
# handler403 = 'home.views.handler403'