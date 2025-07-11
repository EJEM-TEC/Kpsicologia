=== DEBUG: Dados POST recebidos ===
csrfmiddlewaretoken: peMC20gKiJ2cwv4QztHf2vbkLBXpVvcLxU8s7qAIKfiTsQPfynZRyJPWkZGf8IzM
metodo_1390: fechado
patient_inactivation_Lucas Zanini_reason: desistiu
patient_inactivation_Lucas Zanini_notes:
========================================

=== Processando agenda 1390 ===
Método: fechado
Semanal novo: 'None'
Quinzenal novo: 'None'
Semanal original: 'Semanal'
Quinzenal original: 'Lucas Zanini'
Método original: 'padrao'
Pacientes para inativar: ['Lucas Zanini']
Buscando chaves para Lucas Zanini: ['patient_inactivation_Lucas Zanini_reason', 'patient_inactivation_Lucas_Zanini_reason']       
Chave encontrada: patient_inactivation_Lucas Zanini_reason
Tentando inativar paciente: Lucas Zanini
Paciente encontrado: ID 10, Nome: Lucas Zanini
Estado antes: deletado=False, motivo=None
Erro ao inativar paciente Lucas Zanini: type object 'datetime.timezone' has no attribute 'now'
Agenda 1390 salva como fechada
Verificação pós-save - Método: fechado, Semanal: None, Quinzenal: None
[11/Jul/2025 15:41:54] "POST /consultas/editar-multiplas-agendas/36/ HTTP/1.1" 200 71634