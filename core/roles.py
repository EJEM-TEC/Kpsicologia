from rolepermissions.roles import AbstractUserRole

class Administrador(AbstractUserRole):
    available_permissions = {
        'add_user': True,
        'change_user': True,
        'delete_user': True,
        'view_user': True,
    }

class Secretaria(AbstractUserRole):
    available_permissions = {
        'add_user': True,
        'change_user': True,
        'delete_user': True,
        'view_user': True,
    }

class Psicologa(AbstractUserRole):
    available_permissions = {
        'view_user': True,
    }