from django import template

register = template.Library()

@register.filter
def get_item(dictionary, key):
    """
    Filtro personalizado para acessar valores de dicionários no template Django
    
    Uso: {{ meu_dict|get_item:chave }}
    """
    if dictionary and key:
        return dictionary.get(key, {})
    return {}

@register.filter
def get_value(dictionary, key):
    """
    Filtro personalizado para acessar valores específicos de dicionários
    
    Uso: {{ meu_dict|get_value:chave }}
    """
    if dictionary and key:
        return dictionary.get(key, None)
    return None

@register.filter
def multiply(value, arg):
    """
    Multiplica um valor por outro
    
    Uso: {{ valor|multiply:2 }}
    """
    try:
        return float(value) * float(arg)
    except (ValueError, TypeError):
        return 0

@register.filter
def percentage(value, total):
    """
    Calcula a porcentagem
    
    Uso: {{ valor|percentage:total }}
    """
    try:
        if float(total) == 0:
            return 0
        return round((float(value) / float(total)) * 100, 1)
    except (ValueError, TypeError, ZeroDivisionError):
        return 0
