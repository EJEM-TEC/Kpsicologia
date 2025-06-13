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

    # ADMIN
    path("admin/", admin.site.urls),

    # LOGIN E LOGO
    path('logout/', views.logout_user, name="logout"),
    path('login/', views.login, name='login'),
    path('', views.login, name='login1'),

    # MENUS
    path('index/', views.index, name='index'),
    path('cadastros', views.cadastros_menu, name='cadastros'),
    path('consultar_financeiro', views.consultar_financeiro, name='consultar_financeiro'),
    path('disponibilidades_psico', views.disponibilidades_psicologos, name='disponibilidades_psicologos'),

    #USUÁRIOS
    path('users/', views.users, name='users'),
    path("users/<int:user_id>/delete/", views.delete_user, name="delete_user"),
    path("users/<int:user_id>/update/", views.update_user, name="update_user"),

    #UNIDADES
    path('unidades_atendimento/', views.unis, name='unidade_atendimento'),
    path("unidades_atendimento/<int:unidade_id>/update/", views.update_uni, name="update_unidade"),
    path("unidades_atendimento/<int:unidade_id>/delete/", views.delete_uni, name="delete_unidade"),

    #SALAS DE ATENDIMENTO
    path('cadastrar_salas/', views.cadastrar_sala, name='cadastrar_salas'),
    path("cadastrar_salas/<int:id_sala>/update/", views.update_sala, name="update_sala"),
    path("cadastrar_salas/<int:id_sala>/delete/", views.delete_sala, name="delete_sala"),
    path('salas/<int:id_sala>/disponibilidade/', views.definir_horario_sala, name='horario_sala'),
    path('salas/<int:id_sala>/disponibilidade/<int:horario_id>/delete/', views.delete_horario_sala, name='delete_horario_sala'),
    
    #PERFIL DE USUÁRIO
    path('perfil_usuario/', views.perfil, name='perfil_usuario'),
    path('perfil_usuario/<int:user_id>/editar_perfil/', views.update_profile, name='editar_perfil'),

    #PACIENTES   
    path('pacientes/', views.pacientes, name='pacientes'),
    path('pacientes/<int:id_paciente>/editar', views.editar_paciente, name='update_paciente'),
    path('pacientes/<int:id_paciente>/deletar', views.deletar_paciente, name='delete_paciente'),
    path('pacientes/<int:id_paciente>/restaurar', views.restaurar_paciente, name='restaurar_paciente'),

    #PSICÓLOGOS
    path('psicologas/', views.psicologa, name='psicologa'),
    path('visualizar_psicologas', views.visualizar_psicologos, name='visualizar_psicologas'),
    path('deletar_psicologo/<int:psicologo_id>/delete/', views.deletar_psicologo, name='deletar_psicologo'),
    path('editar_psicologo/<int:psicologo_id>/editar/', views.editar_psicologo, name='editar_psicologo'),

    #AGENDA PSICÓLOGO - CONSULTAS
    path('psicologas/<int:psicologo_id>/agendar/', views.psico_agenda, name='psico_agenda'),
    path('consultas/editar/<int:id_consulta>/', views.update_consulta, name='update_consulta'),  # URL para editar consulta
    path('consultas/deletar/<int:id_consulta>/', views.delete_consulta, name='delete_consulta'),  # URL para deletar consulta
    path('consultas/<int:psicologo_id>/deletar_multiplas/', views.delete_multiple_consultas, name='delete_multiple_consultas'),

    #CONFIMAÇÃO DE CONSULTA - PSICÓLOGO
    path('psicologas/<int:psicologo_id>/confirmar/', views.Confirmar_Consulta, name='confirma_consulta'),
    path('psicologas/<int:psicologo_id>/confirmar/adicionar', views.AdicionarConfirma_consulta, name='adiciona_confirma_consulta'),
    path('psicologas/<int:psicologo_id>/<int:consulta_id>/excluir', views.ExcluirConfirma_consulta, name='deletar_confirma_consulta'),
    path('editar_confirmacao_consultas/<int:psicologo_id>', views.editar_confirmacao_consultas, name='editar_consultas'),
    path('adicionar_consulta_emergencial/<int:psicologo_id>', views.adicionarConsultaEmergencial, name='adicionar_consulta_emergencial'),
    path("bloquear_consulta/<int:psicologo_id>/", views.bloquear_consulta, name="bloquear_consulta"),
    path("desbloquear_consulta/<int:psicologo_id>/", views.desbloquear_consulta, name="desbloquear_consulta"),

    #CARACTERÍSTICAS PSICÓLOGO
    path('especialidades', views.cadastrar_especialidade, name='especialidades'),
    path('publicos', views.cadastrar_publico, name='publicos'),
    path('deletar_publico/<int:publico_id>', views.deletar_publico, name='deletar_publico'),
    path('deletar_especialidade/<int:especialidade_id>', views.deletar_especialidade, name='deletar_especialidade'),
    path('psicologo_especialidade/<int:psicologo_id>', views.AssociarPsicoEspecialidade, name='psicoEspecialidades'),
    path('psicologo_especialidade/<int:psicologo_id>/<int:especialidade_id>', views.DissociarPsicoEspecialidade, name='disPsicoEspecialidade'),
    path('psicologo_publico/<int:psicologo_id>', views.AssociarPsicoPublico, name='psicoPublicos'),
    path('psicologo_publico/<int:psicologo_id>/<int:publico_id>', views.DissociarPsicoPublico, name='disPsicoPublico'),
    path('psicologo_unidade/<int:psicologo_id>', views.AssociarPsicoUnidade, name='psicoUnidades'),
    path('psicologo_unidade/<int:psicologo_id>/<int:unidade_id>', views.DissociarPsicoUnidade, name='disPsicoUnidade'),

    #DISPONIBILIDADE PSICÓLOGO
    path('psicologas/<int:psicologo_id>/disponibilidade/', views.definir_disponibilidade_psico, name='psico_disponibilidade'),
    path('deletar_disponibilidade/<int:disponibilidade_id>/<int:psicologo_id>', views.remover_disponibilidade, name='deletar_disponibilidade'),
    path('psicologas/<int:psicologo_id>/remover_disponibilidades/', views.delete_multiple_disponibilidades, name='delete_multiple_disponibilidades'),

    #DISPONIBILIDADE PSICÓLOGO - ONLINE
    path('psicologas/<int:psicologo_id>/disponibilidade_online/', views.disponibilidade_online, name='psico_disponibilidade_online'),
    path('deletar_disponibilidade_online/<int:disponibilidade_online_id>/<int:psicologo_id>', views.remover_disponibilidade_online, name='deletar_disponibilidade_online'),
    path('psicologas/<int:psicologo_id>/remover_disponibilidades_online/', views.delete_multiple_disponibilidades_online, name='delete_multiple_disponibilidades_online'),

    #CONSULTAS ONLINE - PSICÓLOGO
    path('psicologas/<int:psicologo_id>/agendar_online/', views.psico_agenda_online, name='psico_agenda_online'),
    path('deletar_consulta_online/<int:consulta_id>/<int:psicologo_id>', views.delete_consulta_online, name='deletar_consulta_online'),
    path('psicologas/<int:psicologo_id>/deletar_multiplas_online/', views.delete_multiple_consultas_online, name='delete_multiple_consultas_online'),

    #AGENDA CENTRAL
    path('agenda_central', views.agenda_central, name='agenda_central'),
    # path('agenda/relatorio/pdf/', views.gerar_relatorio_pdf_agenda, name='gerar_relatorio_pdf_agenda'),
    # path('agenda/relatorio/visualizar/', views.visualizar_relatorio_agenda, name='visualizar_relatorio_agenda'),   
    
    #PÁGINAS DE ERRO
    path('handler404/', views.handler404, name='handler404'),
    path('consulta_cadastrada1/', views.consulta_cadastrada1, name='consulta_cadastrada1'),
    path('consulta_cadastrada2/', views.consulta_cadastrada2, name='consulta_cadastrada2'),
    path('nome_usuario_erro/', views.nome_usuario_erro, name='nome_usuario_erro'),
    path('login_erro/', views.login_erro, name='login_erro'),
    path('unis_erro/', views.unis_erro, name='unis_erro'),

    #FINANCEIRO
    path('consultar_financeiro/pacientes', views.consulta_financeira_pacientes, name='financeiro_pacientes'),
    path('consultar_financeiro/kpsicologia', views.apuracao_financeira, name='apuracao_financeira_kpsicologia'),
    path('editar_financeiro/<int:id_financeiro>', views.editar_financeiro, name='editar_financeiro'),
    path('financeiro/cliente/<int:id_paciente>/', views.financeiro_cliente_individual, name='financeiro_cliente_individual'),

    #DESPESAS
    path('cadastro_despesa', views.cadastro_despesa, name='cadastro_despesa'),
    path('deletar_despesa/<int:despesa_id>', views.deletar_despesa, name='deletar_despesa'),
     
    #DISPONIBILIDADE HORÁRIOS ATENDIMENTO
    path('consultar_disponibilidade', views.vizualizar_disponibilidade, name='consultar_disponibilidade'),

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