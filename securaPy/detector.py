"""
Modulo 3 - Detector de Anomalias
Analisa o conjunto de eventos para identificar padroes de ataque
que so ficam visiveis quando multiplos eventos sao correlacionados.

Detecta:
- Brute Force: muitas tentativas de login falhas do mesmo IP
- Port Scan: mesmo IP tentando acessar muitas portas distintas
- IPs em Blacklist: IPs conhecidamente maliciosos presentes nos logs
"""


def detectar_brute_force(eventos, threshold=5):
    """
    Identifica IPs com muitas tentativas de login falhas.

    Parametros:
        eventos (list[dict]): lista de eventos normalizados
        threshold (int): numero minimo de falhas para considerar brute force

    Retorna:
        dict: {ip: {"tentativas": N, "usuarios": [...], "severidade": "..."}}
        Apenas IPs com tentativas >= threshold sao incluidos.

    Classificacao de severidade:
        > 20 tentativas: "CRITICA"
        > 10 tentativas: "ALTA"
        > 5  tentativas: "MEDIA"
        >= threshold:    "BAIXA"

    Comportamento esperado:
        - Filtra apenas eventos da fonte "auth" com tipo "FAIL"
        - Conta quantas falhas cada IP teve
        - Registra quais usuarios foram tentados (sem duplicatas)
        - Retorna apenas IPs que atingiram o threshold

    Dicas:
        - Use um dicionario para contar: contagem[ip] = contagem.get(ip, 0) + 1
        - Para usuarios sem duplicata, use um set: usuarios[ip].add(usuario)
        - Filtre no final: {ip: dados for ip, dados in resultado.items() if dados["tentativas"] >= threshold}
    """
    pass


def detectar_port_scan(eventos, threshold=3):
    """
    Identifica IPs que tentaram acessar muitas portas distintas.

    Parametros:
        eventos (list[dict]): lista de eventos normalizados
        threshold (int): numero minimo de portas unicas para considerar port scan

    Retorna:
        dict: {ip: {"portas": set(...), "quantidade": N, "severidade": "..."}}
        Apenas IPs com portas unicas >= threshold sao incluidos.

    Classificacao de severidade:
        > 10 portas: "CRITICA"
        > 5  portas: "ALTA"
        >= threshold: "MEDIA"

    Comportamento esperado:
        - Filtra eventos da fonte "firewall" com tipo "BLOCK"
        - Extrai a porta destino (dport) do campo "detalhes"
        - Usa SET para contar portas unicas por IP (sem duplicatas)

    Dicas:
        - Para extrair dport do detalhes: procure "dport=" no texto
        - Use set() para armazenar portas: portas_por_ip[ip] = set()
        - portas_por_ip[ip].add(porta)
        - quantidade = len(portas_por_ip[ip])
    """
    pass


def verificar_blacklist(eventos, blacklist):
    """
    Cruza os IPs encontrados nos eventos com uma blacklist conhecida.

    Parametros:
        eventos (list[dict]): lista de eventos normalizados
        blacklist (set): conjunto de IPs maliciosos conhecidos

    Retorna:
        tuple: (ips_encontrados, contagem_por_ip)
        - ips_encontrados (set): IPs que estao na blacklist E nos eventos
        - contagem_por_ip (dict): {ip: numero_de_eventos} para cada IP da blacklist

    Comportamento esperado:
        - Extrai todos os IPs unicos dos eventos (use um set)
        - Faz a INTERSECAO com a blacklist para encontrar os maliciosos
        - Conta quantos eventos cada IP malicioso gerou

    Dicas:
        - ips_eventos = {evento["ip"] for evento in eventos}  # set comprehension
        - ips_encontrados = ips_eventos & blacklist  # intersecao de sets
        - Para contar, itere pelos eventos e incremente se ip esta em ips_encontrados
    """
    pass


def gerar_resumo_ameacas(brute_force, port_scan, blacklist_resultado):
    """
    Consolida todas as deteccoes em um resumo unificado de ameacas.

    Parametros:
        brute_force (dict): resultado de detectar_brute_force()
        port_scan (dict): resultado de detectar_port_scan()
        blacklist_resultado (tuple): resultado de verificar_blacklist() -> (set, dict)

    Retorna:
        list[dict]: lista de ameacas ordenada por pontuacao (maior primeiro)
        Cada ameaca eh um dict com:
        {
            "ip": "185.220.101.1",
            "deteccoes": ["brute_force", "port_scan", "blacklist"],
            "pontuacao": 15,
            "severidade": "CRITICA",
            "detalhes": { ... resumo de cada deteccao ... }
        }

    Comportamento esperado:
        - Junta todos os IPs suspeitos das 3 deteccoes
        - Para cada IP, lista em quais deteccoes apareceu
        - Calcula pontuacao: brute_force=5pts, port_scan=5pts, blacklist=5pts
          (IPs com multiplas deteccoes tem pontuacao somada)
        - Classifica severidade pela pontuacao total
        - Ordena do mais critico para o menos

    Dicas:
        - Junte os IPs: todos_ips = set(brute_force.keys()) | set(port_scan.keys()) | blacklist_ips
        - Use um loop para verificar em quais deteccoes cada IP aparece
        - Use sorted() com key=lambda para ordenar por pontuacao
    """
    pass
