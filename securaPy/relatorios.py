"""
Modulo 6 - Dashboard CLI e Relatorios
Interface interativa do SIEM com menu de opcoes, filtros de eventos,
busca por IP, ranking de ameacas e exportacao de relatorios em JSON.
"""

import json
import os
from datetime import datetime


def exibir_menu():
    """
    Exibe o menu principal do SecuraPy e retorna a opcao escolhida.

    Retorna:
        int: numero da opcao escolhida (0-9)
        Retorna -1 se o usuario digitar algo invalido.

    Comportamento esperado:
        - Exibe o menu formatado com as opcoes numeradas (0-9)
        - Le a entrada do usuario com input()
        - Converte para int e retorna
        - Se a entrada nao for um numero valido, retorna -1

    Menu:
        1. Carregar e processar logs
        2. Resumo geral
        3. Filtrar eventos
        4. Buscar IP
        5. Top 10 IPs suspeitos
        6. Ver alertas por severidade
        7. Enriquecer IPs suspeitos
        8. Exportar relatorio JSON
        9. Iniciar servidor de alertas
        0. Sair

    Dicas:
        - Use print() para desenhar o menu
        - Envolva int(input()) em try/except ValueError
    """
    pass


def resumo_geral(eventos, alertas):
    """
    Exibe um resumo com contadores gerais do processamento.

    Parametros:
        eventos (list[dict]): todos os eventos carregados
        alertas (list[dict]): todos os alertas gerados

    Comportamento esperado:
        - Conta eventos por fonte (auth, firewall, web)
        - Conta alertas por severidade (CRITICA, ALTA, MEDIA, BAIXA, INFO)
        - Exibe total geral de eventos e alertas
        - Formata como tabela legivel

    Dicas:
        - Use dicionario como contador: contadores = {}
        - contadores[fonte] = contadores.get(fonte, 0) + 1
        - Faca o mesmo para severidades dos alertas
    """
    pass


def filtrar_eventos(eventos, fonte=None, tipo=None, ip=None):
    """
    Filtra eventos pelos criterios fornecidos.

    Parametros:
        eventos (list[dict]): lista de eventos
        fonte (str ou None): filtrar por fonte ("auth", "firewall", "web")
        tipo (str ou None): filtrar por tipo ("FAIL", "BLOCK", "GET", etc.)
        ip (str ou None): filtrar por endereco IP

    Retorna:
        list[dict]: eventos que atendem TODOS os criterios fornecidos
        Criterios None sao ignorados (nao filtram).

    Dicas:
        - Use list comprehension com condicoes
        - Para cada criterio que nao for None, adicione uma condicao
        - Exemplo: [e for e in eventos if (fonte is None or e["fonte"] == fonte)]
    """
    pass


def buscar_ip(ip, eventos, alertas, cache_enriquecimento):
    """
    Exibe relatorio completo de um IP: eventos, alertas e geolocalizacao.

    Parametros:
        ip (str): endereco IP a buscar
        eventos (list[dict]): todos os eventos
        alertas (list[dict]): todos os alertas
        cache_enriquecimento (dict): cache de consultas de IP

    Comportamento esperado:
        - Filtra eventos desse IP
        - Filtra alertas desse IP
        - Consulta enriquecimento (se disponivel)
        - Exibe tudo formatado

    Dicas:
        - Reutilize filtrar_eventos(eventos, ip=ip)
        - Para alertas: [a for a in alertas if a["ip"] == ip]
    """
    pass


def top_ips(eventos, n=10):
    """
    Retorna os N IPs com mais eventos registrados.

    Parametros:
        eventos (list[dict]): lista de eventos
        n (int): quantidade de IPs a retornar (padrao: 10)

    Retorna:
        list[tuple]: lista de tuplas (ip, contagem) ordenada por contagem decrescente

    Dicas:
        - Use dicionario para contar eventos por IP
        - Converta para lista de tuplas: list(contagem.items())
        - Ordene com sorted(lista, key=lambda x: x[1], reverse=True)
        - Retorne apenas os primeiros N: resultado[:n]
    """
    pass


def exportar_relatorio_json(dados, caminho):
    """
    Salva um relatorio completo em formato JSON.

    Parametros:
        dados (dict): dicionario com todos os dados do relatorio
        caminho (str): caminho do arquivo de saida

    Comportamento esperado:
        - Cria o diretorio de saida se nao existir
        - Salva o JSON formatado com indent=2 e ensure_ascii=False
        - Imprime confirmacao com o caminho do arquivo salvo

    Dicas:
        - Use os.makedirs(os.path.dirname(caminho), exist_ok=True)
        - Use json.dump(dados, f, indent=2, ensure_ascii=False)
        - Converta sets para listas antes de salvar (JSON nao suporta set)
    """
    pass


def exibir_tabela(dados, colunas):
    """
    Exibe uma lista de dicionarios como tabela formatada no terminal.

    Parametros:
        dados (list[dict]): lista de dicionarios a exibir
        colunas (list[str]): chaves a exibir como colunas

    Comportamento esperado:
        - Exibe cabecalho com os nomes das colunas
        - Exibe separador (linha de tracos)
        - Exibe cada linha de dados alinhada com as colunas
        - Se dados estiver vazio, exibe "Nenhum dado encontrado"

    Dicas:
        - Calcule a largura de cada coluna: max(len(str(d[col])) for d in dados)
        - Use f-string com largura: f"{valor:<{largura}}"
    """
    pass
