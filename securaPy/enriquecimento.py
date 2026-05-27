"""
Modulo 5 - Enriquecimento de IPs
Adiciona contexto geografico e organizacional aos IPs suspeitos
consultando a API publica do ipinfo.io.

Classifica IPs em privados (rede interna) e publicos, e consulta
apenas os publicos para economizar requisicoes.

Formato do resultado de enriquecimento:
{
    "ip": "185.220.101.1",
    "privado": False,
    "cidade": "Frankfurt am Main",
    "regiao": "Hesse",
    "pais": "DE",
    "org": "AS208294 Fastethernet",
    "hostname": "tor-exit.r2"
}
"""

import requests
import json


def eh_ip_privado(ip):
    """
    Verifica se um endereco IP pertence a uma faixa de rede privada (RFC 1918).

    Parametros:
        ip (str): endereco IPv4 no formato "x.x.x.x"

    Retorna:
        bool: True se o IP for privado, False se for publico

    Faixas privadas:
        10.0.0.0    - 10.255.255.255   (10.x.x.x)
        172.16.0.0  - 172.31.255.255   (172.16-31.x.x)
        192.168.0.0 - 192.168.255.255  (192.168.x.x)
        127.0.0.0   - 127.255.255.255  (127.x.x.x - loopback)

    Dicas:
        - Use ip.split(".") para separar os octetos
        - Converta para int: octetos = [int(x) for x in ip.split(".")]
        - Verifique cada faixa com condicionais
        - Lembre de verificar 172.16-31 (segundo octeto entre 16 e 31)
    """
    pass


def consultar_ip(ip, cache):
    """
    Consulta a API do ipinfo.io para obter informacoes de geolocalizacao.

    Parametros:
        ip (str): endereco IP publico a ser consultado
        cache (dict): dicionario usado como cache de consultas anteriores

    Retorna:
        dict: informacoes do IP com chaves: ip, cidade, regiao, pais, org, hostname
        Retorna dict com valores "Desconhecido" em caso de erro.

    Comportamento esperado:
        - Se o IP ja estiver no cache, retorna do cache sem consultar a API
        - Se for IP privado, retorna dados fixos ("Rede Interna") sem consultar
        - Faz GET em https://ipinfo.io/{ip}/json com timeout de 5 segundos
        - Armazena resultado no cache antes de retornar
        - Trata: ConnectionError, Timeout, status != 200, JSONDecodeError

    Dicas:
        - if ip in cache: return cache[ip]
        - resposta = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        - dados = resposta.json()
        - Use dados.get("city", "Desconhecido") para valores opcionais
        - cache[ip] = resultado  (salva no cache)
    """
    pass


def enriquecer_alertas(alertas, cache):
    """
    Adiciona informacoes de geolocalizacao a uma lista de alertas.

    Parametros:
        alertas (list[dict]): lista de alertas (cada um tem campo "ip")
        cache (dict): cache de consultas de IP

    Retorna:
        list[dict]: mesmos alertas com campo adicional "geolocalizacao"

    Comportamento esperado:
        - Para cada alerta, consulta o IP (usando cache)
        - Adiciona campo "geolocalizacao" ao alerta com os dados retornados
        - IPs privados recebem geolocalizacao com "Rede Interna"
        - IPs repetidos usam o cache (sem consulta duplicada)

    Dicas:
        - Extraia IPs unicos primeiro para minimizar consultas
        - Use um set para coletar IPs unicos: ips = {a["ip"] for a in alertas}
        - Consulte cada IP unico uma vez, depois distribua pelos alertas
    """
    pass


def exibir_enriquecimento(dados_ip):
    """
    Exibe as informacoes de um IP de forma formatada no terminal.

    Parametros:
        dados_ip (dict): dicionario retornado por consultar_ip()

    Comportamento esperado:
        - Exibe IP, cidade, regiao, pais e organizacao de forma legivel
        - Indica se eh IP privado ou publico

    Dicas:
        - Use f-strings com alinhamento: f"{'IP:':<15} {dados['ip']}"
    """
    pass
