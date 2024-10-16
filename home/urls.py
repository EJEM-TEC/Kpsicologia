from django.urls import path
from home import views
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import LogoutView


urlpatterns = [
    path('', views.login, name='login1'),
    path('index/', views.index, name='index'),
    path('billing/', views.billing, name='billing'),
    path('tables/', views.tables, name='tables'),
    path('vr/', views.vr, name='vr'),
    path('rtl/', views.rtl, name='rtl'),
    path('profile/', views.profile, name='profile'),
    path('users/', views.users, name='users'),
    path('logout/', LogoutView.as_view(), name="logout"),
    path('login/', views.login, name='login'),
    path('unidades_atendimento/', views.unis, name='unidade_atendimento'),
    path("users/<int:user_id>/delete/", views.delete_user, name="delete_user"),
    path("users/<int:user_id>/update/", views.update_user, name="update_user"),

    # Authentication
    #path('accounts/login/', views.UserLoginView.as_view(), name='login'),
    #path('accounts/logout/', views.logout_view, name='logout'),
    # path('accounts/register/', views.register, name='register'),
    # path('accounts/password-change/', views.UserPasswordChangeView.as_view(), name='password_change'),
    # path('accounts/password-change-done/', auth_views.PasswordChangeDoneView.as_view(
    #     template_name='accounts/password_change_done.html'
    # ), name="password_change_done"),
    # path('accounts/password-reset/', views.UserPasswordResetView.as_view(), name='password_reset'),
    # path('accounts/password-reset-confirm/<uidb64>/<token>/', 
    #     views.UserPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    # path('accounts/password-reset-done/', auth_views.PasswordResetDoneView.as_view(
    #     template_name='accounts/password_reset_done.html'
    # ), name='password_reset_done'),
    # path('accounts/password-reset-complete/', auth_views.PasswordResetCompleteView.as_view(
    #     template_name='accounts/password_reset_complete.html'
    # ), name='password_reset_complete'),
]
