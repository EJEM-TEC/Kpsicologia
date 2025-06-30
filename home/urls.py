from django.urls import path
from home import views
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import LogoutView
from .views import lista_consultas, create_consulta, update_consulta, delete_consulta  # Importando as views de consultas

urlpatterns = [
    path('', views.index, name='index'),   
]
