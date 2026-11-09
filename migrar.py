"""
Migracao inicial: le os logs pelo nucleo do 1o semestre e popula o MongoDB.

Uso (a partir da raiz do projeto):
    python migrar.py
"""

import sys
from datetime import datetime

from core import coletor, detector, regras
from db import mongo_repo

PASTA_LOGS = "logs"
ARQUIVO_REGRAS = "config/regras.json"

# TROQUE pela blacklist real do 1o semestre (a mesma usada no main.py antigo).
BLACKLIST = ["185.220.101.1"]


def ameacas_para_alertas(brute, scan, blacklist_ips):
    """
    Converte os achados do detector (brute force, port scan, blacklist) para o
    MESMO formato de alerta do motor de regras, para viverem na mesma colecao.
    """
    agora = datetime.now().strftime(mongo_repo.FORMATO_TS)
    alertas = []
    for ip, d in brute.items():
        alertas.append({
            "timestamp": agora, "regra_id": "DET-BF", "regra_nome": "Brute Force",
            "severidade": d["severidade"], "ip": ip,
            "descricao": f"{d['tentativas']} tentativas de login falhas "
                         f"(usuarios: {', '.join(d['usuarios'])})",
        })
    for ip, d in scan.items():
        alertas.append({
            "timestamp": agora, "regra_id": "DET-PS", "regra_nome": "Port Scan",
            "severidade": d["severidade"], "ip": ip,
            "descricao": f"{d['quantidade']} portas distintas bloqueadas",
        })
    for ip in blacklist_ips:
        alertas.append({
            "timestamp": agora, "regra_id": "DET-BL", "regra_nome": "IP em Blacklist",
            "severidade": "ALTA", "ip": ip,
            "descricao": "IP presente na lista de IPs maliciosos conhecidos",
        })
    return alertas


def main():
    eventos = coletor.carregar_todos_os_logs(PASTA_LOGS)
    if not eventos:
        print("[ERRO] Nenhum evento carregado. Verifique a pasta de logs.")
        return 1

    regras_ativas = regras.carregar_regras(ARQUIVO_REGRAS)
    alertas = regras.aplicar_regras(eventos, regras_ativas)

    brute = detector.detectar_brute_force(eventos)
    scan = detector.detectar_port_scan(eventos)
    ips_blacklist, _ = detector.verificar_blacklist(eventos, BLACKLIST)
    alertas += ameacas_para_alertas(brute, scan, ips_blacklist)

    try:
        mongo_repo.criar_indices()
        n_eventos = mongo_repo.salvar_eventos(eventos, substituir=True)
        n_alertas = mongo_repo.salvar_alertas(alertas, substituir=True)
    except mongo_repo.RepositorioErro as erro:
        print(f"[ERRO] {erro}")
        return 1

    print(f"[MIGRACAO] {n_eventos} evento(s) e {n_alertas} alerta(s) persistidos.")
    print(f"[MIGRACAO] Por fonte: {mongo_repo.contagem_por_fonte()}")
    print(f"[MIGRACAO] Top 5 IPs: {mongo_repo.top_ips(5)}")
    if n_eventos != 58:
        print(f"[AVISO] Esperado 58 eventos (cenario B1), obtido {n_eventos}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())