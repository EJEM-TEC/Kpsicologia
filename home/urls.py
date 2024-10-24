from django.urls import path
from home import views
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import LogoutView
from .views import lista_consultas, create_consulta, update_consulta, delete_consulta  # Importando as views de consultas

urlpatterns = [
    path('', views.index, name='index'),   
    
    # URLs para gerenciamento de consultas
    path('consultas/', lista_consultas, name='lista_consultas'),  # URL para listar consultas
    path('consultas/novo/', create_consulta, name='create_consulta'),  # URL para criar nova consulta
    path('consultas/editar/<int:consulta_id>/', update_consulta, name='update_consulta'),  # URL para editar consulta
    path('consultas/deletar/<int:consulta_id>/', delete_consulta, name='delete_consulta'),  # URL para deletar consulta
]
