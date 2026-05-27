"""
Modulo 2 - Motor de Regras
Responsavel por carregar regras de deteccao de um arquivo JSON,
avaliar cada evento contra as regras ativas e gerar alertas
quando uma regra eh violada.

Formato de um alerta gerado:
{
    "timestamp": "2025-02-20 08:15:01",
    "regra_id": "R001",
    "regra_nome": "Login com Usuario Privilegiado",
    "severidade": "MEDIA",
    "ip": "185.220.101.1",
    "descricao": "Tentativa de login com usuario admin"
}

Niveis de severidade (baseados na pontuacao):
    >= 9: CRITICA
    >= 7: ALTA
    >= 5: MEDIA
    >= 3: BAIXA
     < 3: INFO
"""

import json


def carregar_regras(caminho_config):
    """
    Le o arquivo regras.json e retorna a lista de regras.

    Parametros:
        caminho_config (str): caminho para o arquivo JSON de regras

    Retorna:
        list[dict]: lista de dicionarios, cada um representando uma regra
        Retorna lista vazia se o arquivo nao existir ou JSON for invalido.
    """
    try:
        with open(caminho_config, "r", encoding="utf-8") as f:
            dados = json.load(f)
        # Suporta tanto {"regras": [...]} quanto lista direta [...]
        if isinstance(dados, dict):
            regras = dados.get("regras", [])
        else:
            regras = dados
        # Filtra apenas regras ativas
        regras_ativas = [r for r in regras if r.get("ativa", False)]
        print(f"[REGRAS] {len(regras_ativas)} regra(s) ativa(s) carregada(s).")
        return regras_ativas
    except FileNotFoundError:
        print(f"[ERRO] Arquivo de regras nao encontrado: {caminho_config}")
        return []
    except json.JSONDecodeError as e:
        print(f"[ERRO] JSON invalido em '{caminho_config}': {e}")
        return []


def classificar_severidade(pontuacao):
    """
    Converte uma pontuacao numerica em nivel de severidade.

    Parametros:
        pontuacao (int ou float): valor numerico da severidade

    Retorna:
        str: "CRITICA", "ALTA", "MEDIA", "BAIXA" ou "INFO"
    """
    if pontuacao >= 9:
        return "CRITICA"
    elif pontuacao >= 7:
        return "ALTA"
    elif pontuacao >= 5:
        return "MEDIA"
    elif pontuacao >= 3:
        return "BAIXA"
    else:
        return "INFO"


def avaliar_regra(regra, evento):
    """
    Avalia se um evento viola uma regra especifica.

    Parametros:
        regra (dict): dicionario da regra (do JSON de configuracao)
        evento (dict): dicionario do evento normalizado (do coletor)

    Retorna:
        dict: alerta gerado se a regra foi violada
        None: se o evento nao viola a regra
    """
    # Verifica se a fonte do evento bate com a fonte da regra
    if evento.get("fonte") != regra.get("fonte"):
        return None

    condicao = regra.get("condicao")
    detalhes = evento.get("detalhes", "")
    url = ""

    # --- R001: usuario_privilegiado ---
    if condicao == "usuario_privilegiado":
        # Extrai o usuario do campo detalhes (ex: "usuario=admin")
        usuario = ""
        for parte in detalhes.split():
            if parte.startswith("usuario="):
                usuario = parte.split("=", 1)[1]
                break
        if usuario not in regra.get("usuarios_alvo", []):
            return None
        descricao = f"Tentativa de login com usuario {usuario}"

    # --- R002: porta_critica ---
    elif condicao == "porta_critica":
        # Apenas eventos BLOCK interessam
        if evento.get("tipo") != "BLOCK":
            return None
        # Extrai dport do campo detalhes (ex: "proto=TCP dst=10.0.0.1 dport=22")
        porta = None
        for parte in detalhes.split():
            if parte.startswith("dport="):
                try:
                    porta = int(parte.split("=", 1)[1])
                except ValueError:
                    return None
                break
        if porta is None or porta not in regra.get("portas_criticas", []):
            return None
        descricao = f"Acesso bloqueado na porta critica {porta}"

    # --- R003: path_traversal ---
    elif condicao == "path_traversal":
        # Extrai a URL do campo detalhes (ex: "url=/../../etc/passwd status=400")
        for parte in detalhes.split():
            if parte.startswith("url="):
                url = parte.split("=", 1)[1]
                break
        if not any(padrao in url for padrao in regra.get("padroes", [])):
            return None
        descricao = f"Tentativa de path traversal na URL: {url}"

    # --- R004: xss ---
    elif condicao == "xss":
        for parte in detalhes.split():
            if parte.startswith("url="):
                url = parte.split("=", 1)[1]
                break
        if not any(padrao in url for padrao in regra.get("padroes", [])):
            return None
        descricao = f"Tentativa de XSS na URL: {url}"

    # --- R005: reconhecimento ---
    elif condicao == "reconhecimento":
        for parte in detalhes.split():
            if parte.startswith("url="):
                url = parte.split("=", 1)[1]
                break
        urls_suspeitas = regra.get("urls_suspeitas", [])
        if not any(suspeita in url for suspeita in urls_suspeitas):
            return None
        descricao = f"Acesso a URL de reconhecimento: {url}"

    else:
        # Condicao desconhecida — ignora
        return None

    # Monta o alerta
    severidade = classificar_severidade(regra.get("severidade_base", 0))
    alerta = {
        "timestamp": evento.get("timestamp", ""),
        "regra_id": regra.get("id", ""),
        "regra_nome": regra.get("nome", ""),
        "severidade": severidade,
        "ip": evento.get("ip", ""),
        "descricao": descricao,
    }
    return alerta


def aplicar_regras(eventos, regras):
    """
    Aplica todas as regras a todos os eventos e retorna os alertas gerados.

    Parametros:
        eventos (list[dict]): lista de eventos normalizados
        regras (list[dict]): lista de regras ativas

    Retorna:
        list[dict]: lista de alertas gerados
    """
    alertas = []
    for evento in eventos:
        for regra in regras:
            resultado = avaliar_regra(regra, evento)
            if resultado is not None:
                alertas.append(resultado)
    print(f"[REGRAS] {len(alertas)} alerta(s) gerado(s).")
    return alertas


# ----- Teste rapido local -----
if __name__ == "__main__":
    # Evento de teste - login admin
    evento_auth = {
        "timestamp": "2025-02-20 08:15:01",
        "fonte": "auth",
        "tipo": "FAIL",
        "ip": "185.220.101.1",
        "detalhes": "usuario=admin",
        "linha_original": "2025-02-20 08:15:01 FAIL usuario=admin ip=185.220.101.1",
    }

    # Evento de teste - porta critica
    evento_fw = {
        "timestamp": "2025-02-20 08:10:02",
        "fonte": "firewall",
        "tipo": "BLOCK",
        "ip": "185.220.101.1",
        "detalhes": "proto=TCP dst=10.0.0.1 dport=22",
        "linha_original": "",
    }

    # Evento de teste - path traversal
    evento_web = {
        "timestamp": "2025-02-20 08:20:08",
        "fonte": "web",
        "tipo": "GET",
        "ip": "91.240.118.172",
        "detalhes": "url=/../../etc/passwd status=400",
        "linha_original": "",
    }

    regras = carregar_regras("config/regras.json")

    for ev in [evento_auth, evento_fw, evento_web]:
        alertas = aplicar_regras([ev], regras)
        for a in alertas:
            print(f"  [{a['severidade']}] {a['regra_nome']} | IP: {a['ip']} | {a['descricao']}")