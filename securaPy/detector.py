"""
Modulo 3 - Detector de Anomalias
Analisa o conjunto de eventos para identificar padroes de ataque
que so ficam visiveis quando multiplos eventos sao correlacionados.

Desenvolvido por: Maick

Detecta:
- Brute Force: muitas tentativas de login falhas do mesmo IP
- Port Scan: mesmo IP tentando acessar muitas portas distintas
- IPs em Blacklist: IPs conhecidamente maliciosos presentes nos logs
"""

from collections import defaultdict


def detectar_brute_force(eventos, threshold=5):
    """
    Identifica IPs com muitas tentativas de login falhas.
    Agrupa falhas por IP e contabiliza os usuarios tentados.

    Retorna dict: {ip: {"tentativas": N, "usuarios": [...], "severidade": "..."}}
    Apenas IPs com tentativas >= threshold sao incluidos.
    """
    contagem = defaultdict(lambda: {"tentativas": 0, "usuarios": set()})

    for evento in eventos:
        # Filtra apenas eventos de autenticacao com falha
        if evento.get("fonte") == "auth" and evento.get("tipo") == "FAIL":
            ip = evento.get("ip")
            contagem[ip]["tentativas"] += 1
            if evento.get("usuario"):
                contagem[ip]["usuarios"].add(evento.get("usuario"))

    resultado = {}
    for ip, dados in contagem.items():
        n = dados["tentativas"]
        if n >= threshold:
            # Severidade escala conforme o volume de tentativas
            if n > 20:
                severidade = "CRITICA"
            elif n >= 10:
                severidade = "ALTA"
            elif n >= 5:
                severidade = "MEDIA"
            else:
                severidade = "BAIXA"

            resultado[ip] = {
                "tentativas": n,
                "usuarios": list(dados["usuarios"]),
                "severidade": severidade
            }

    return resultado


def detectar_port_scan(eventos, threshold=3):
    """
    Detecta varredura de portas observando bloqueios do firewall.
    Um IP que tenta acessar muitas portas distintas esta fazendo port scan.

    Retorna dict: {ip: {"portas": [...], "quantidade": N, "severidade": "..."}}
    Apenas IPs com portas unicas >= threshold sao incluidos.
    """
    portas_por_ip = defaultdict(set)

    for evento in eventos:
        # Foca em bloqueios de firewall com porta de destino registrada
        if evento.get("fonte") == "firewall" and evento.get("tipo") == "BLOCK":
            ip = evento.get("ip")
            dport = evento.get("dport")
            if ip and dport:
                portas_por_ip[ip].add(dport)

    resultado = {}
    for ip, portas in portas_por_ip.items():
        quantidade = len(portas)
        if quantidade >= threshold:
            # Quanto mais portas, mais suspeito
            if quantidade > 10:
                severidade = "CRITICA"
            elif quantidade >= 6:
                severidade = "ALTA"
            else:
                severidade = "MEDIA"

            resultado[ip] = {
                "portas": list(portas),
                "quantidade": quantidade,
                "severidade": severidade
            }

    return resultado


def verificar_blacklist(eventos, blacklist):
    """
    Cruza os IPs dos logs com uma lista de IPs maliciosos conhecidos.
    Usa intersecao de sets para encontrar matches de forma eficiente.

    Retorna o set de IPs maliciosos encontrados nos logs.
    """
    # Coleta todos os IPs unicos dos eventos
    ips_nos_logs = {evento.get("ip") for evento in eventos if evento.get("ip")}

    # Intersecao: IPs que estao nos logs E na blacklist
    return ips_nos_logs & blacklist


def gerar_resumo_ameacas(brute, scan, blacklist):
    """
    Consolida os achados dos tres detectores em uma lista unificada.
    IPs que aparecem em multiplas deteccoes recebem severidade mais alta.

    Retorna lista de dicts ordenada por nivel de ameaca (mais critico primeiro).
    """
    # Mapeamento de severidade para valor numerico (facilita comparacoes)
    MAPA_SEVERIDADE = {"CRITICA": 4, "ALTA": 3, "MEDIA": 2, "BAIXA": 1}
    MAPA_INVERSO = {v: k for k, v in MAPA_SEVERIDADE.items()}

    # Junta todos os IPs suspeitos das tres fontes
    todos_ips = set(brute.keys()) | set(scan.keys()) | set(blacklist)

    resumo = []
    for ip in todos_ips:
        motivos = []
        niveis = []

        # Verifica em quais deteccoes o IP apareceu
        if ip in brute:
            motivos.append("Forca Bruta")
            niveis.append(MAPA_SEVERIDADE[brute[ip]["severidade"]])

        if ip in scan:
            motivos.append("Port Scan")
            niveis.append(MAPA_SEVERIDADE[scan[ip]["severidade"]])

        if ip in blacklist:
            motivos.append("Blacklist")
            niveis.append(3)  # Blacklist = severidade ALTA minima

        # Logica de risco composto: mais motivos = maior severidade
        quantidade_motivos = len(motivos)
        nivel_base = max(niveis) if niveis else 1

        if quantidade_motivos >= 3:
            nivel_final = 4  # CRITICA se aparecer nas 3 deteccoes
        elif quantidade_motivos == 2:
            nivel_final = min(nivel_base + 1, 4)  # Sobe um nivel
        else:
            nivel_final = nivel_base

        resumo.append({
            "ip": ip,
            "motivos": motivos,
            "severidade": MAPA_INVERSO[nivel_final]
        })

    # Ordena do mais critico para o menos
    resumo.sort(key=lambda x: MAPA_SEVERIDADE.get(x["severidade"], 0), reverse=True)
    return resumo