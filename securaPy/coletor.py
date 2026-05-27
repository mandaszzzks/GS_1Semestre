"""
Modulo 1 - Coletor de Logs
Responsavel por ler arquivos de log de diferentes fontes (auth, firewall, web),
parsear cada linha e normalizar os eventos em um formato padronizado de dicionario.

Formato padronizado de evento:
{
    "timestamp": "2025-02-20 08:15:01",
    "fonte": "auth",              # auth | firewall | web
    "tipo": "FAIL",               # OK | FAIL | BLOCK | ALLOW | GET | POST | DELETE
    "ip": "185.220.101.1",
    "detalhes": "usuario=admin",  # informacoes extras dependendo da fonte
    "linha_original": "..."       # linha crua do log
}
"""

import os


def parsear_linha_auth(linha):
    """
    Parseia uma linha do auth.log e retorna um dicionario normalizado.

    Formato da linha:
        "2025-02-20 08:15:01 FAIL usuario=admin ip=185.220.101.1"

    Retorna:
        dict com chaves: timestamp, fonte, tipo, ip, detalhes, linha_original
        Retorna None se a linha estiver em formato invalido.

    Dicas:
        - Use split() para separar a linha em partes
        - O timestamp sao as 2 primeiras partes juntas (data + hora)
        - O tipo eh a terceira parte (FAIL ou OK)
        - Percorra as partes restantes procurando "ip=" e "usuario="
    """
    pass


def parsear_linha_firewall(linha):
    """
    Parseia uma linha do firewall.log e retorna um dicionario normalizado.

    Formato da linha:
        "2025-02-20 08:10:02 BLOCK proto=TCP src=185.220.101.1 dst=10.0.0.1 dport=22"

    Retorna:
        dict com chaves: timestamp, fonte, tipo, ip, detalhes, linha_original
        - O campo "ip" deve conter o IP de origem (src)
        - O campo "detalhes" deve conter proto, dst e dport concatenados
        Retorna None se a linha estiver em formato invalido.

    Dicas:
        - Mesmo principio do auth: split() e procure os campos com "="
        - O IP relevante para seguranca eh o src (origem da conexao)
    """
    pass


def parsear_linha_web(linha):
    """
    Parseia uma linha do web_access.log e retorna um dicionario normalizado.

    Formato da linha:
        "2025-02-20 08:20:01 GET url=/index.html ip=192.168.1.10 status=200"

    Retorna:
        dict com chaves: timestamp, fonte, tipo, ip, detalhes, linha_original
        - O campo "tipo" deve conter o metodo HTTP (GET, POST, DELETE, etc.)
        - O campo "detalhes" deve conter url e status
        Retorna None se a linha estiver em formato invalido.

    Dicas:
        - O metodo HTTP eh a terceira parte da linha (apos data e hora)
        - Cuidado: a URL pode conter caracteres especiais (ex: <script>)
    """
    pass


def carregar_log(caminho_arquivo, fonte):
    """
    Le um arquivo de log e retorna uma lista de eventos normalizados.

    Parametros:
        caminho_arquivo (str): caminho do arquivo de log
        fonte (str): tipo da fonte - "auth", "firewall" ou "web"

    Retorna:
        list[dict]: lista de eventos normalizados (dicionarios)
        Retorna lista vazia se o arquivo nao existir ou estiver vazio.

    Comportamento esperado:
        - Se o arquivo nao existir, imprime mensagem de erro e retorna []
        - Se uma linha estiver mal formatada, imprime aviso e pula para a proxima
        - Linhas em branco devem ser ignoradas silenciosamente

    Dicas:
        - Use try/except FileNotFoundError para tratar arquivo inexistente
        - Use with open(caminho, "r") as f: para abrir o arquivo
        - Chame a funcao de parsing correta baseado no parametro "fonte"
        - Use if/elif para escolher: parsear_linha_auth, parsear_linha_firewall, parsear_linha_web
    """
    pass


def carregar_todos_os_logs(pasta_logs):
    """
    Le todos os arquivos de log da pasta e retorna uma lista unificada de eventos.

    Parametros:
        pasta_logs (str): caminho da pasta contendo os arquivos de log

    Retorna:
        list[dict]: lista com todos os eventos de todas as fontes

    Comportamento esperado:
        - Identifica a fonte pelo nome do arquivo (auth.log -> "auth", etc.)
        - Ignora arquivos que nao sejam .log
        - Imprime quantos eventos foram carregados de cada arquivo

    Dicas:
        - Use os.listdir(pasta) para listar os arquivos
        - Use arquivo.endswith(".log") para filtrar
        - Use "auth" in arquivo para identificar a fonte
        - Chame carregar_log() para cada arquivo encontrado
    """
    pass
