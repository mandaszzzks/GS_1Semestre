"""API de operações do VioTrace que reutiliza os módulos Python do SecuraPy.
Executar somente em ambiente local de laboratório. Não executa comandos do shell.
"""
from collections import Counter
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
import hashlib
import hmac
import json
import os
import shutil
import socket
import sys
import tempfile
import threading

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel

from seguranca import exigir_usuario, ler_usuario

BACKEND = Path(__file__).resolve().parent
RAIZ = BACKEND.parent
SECURAPY = RAIZ / "core"
LOGS = RAIZ / "logs"
CONFIG = RAIZ / "config" / "regras.json"
RELATORIO = BACKEND / "dados" / "relatorio.json"
LOCK = threading.RLock()
TCP_THREAD = None

if not SECURAPY.is_dir():
    raise RuntimeError(f"Pasta securaPy não encontrada em {SECURAPY}")
for _pasta in (SECURAPY, RAIZ / "alertas"):
    if str(_pasta) not in sys.path:
        sys.path.insert(0, str(_pasta))

from coletor import carregar_todos_os_logs
from regras import carregar_regras, aplicar_regras
from detector import (
    detectar_brute_force,
    detectar_port_scan,
    verificar_blacklist,
    gerar_resumo_ameacas,
)
from enriquecimento import enriquecer_alertas
from relatorios import filtrar_eventos
import servidor_alertas as tcp

BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}
router = APIRouter(prefix="/api/siem", tags=["Operações SIEM"])


def exigir_admin(usuario: str = Depends(exigir_usuario)):
    admin = str(ler_usuario().get("usuario", ""))
    if not hmac.compare_digest(usuario.casefold(), admin.casefold()):
        raise HTTPException(403, "Apenas o administrador pode executar esta operação.")
    return usuario


def ler_relatorio():
    try:
        dados = json.loads(RELATORIO.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise HTTPException(503, "Relatório indisponível. Processe os logs primeiro.")
    if not isinstance(dados, dict) or not isinstance(dados.get("alertas"), list):
        raise HTTPException(503, "Relatório inválido.")
    return dados


def salvar_json_arquivo(caminho: Path, dados):
    caminho.parent.mkdir(parents=True, exist_ok=True)
    nome_tmp = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=caminho.parent,
            prefix=".viotrace-", suffix=".tmp", delete=False
        ) as arquivo:
            nome_tmp = arquivo.name
            json.dump(dados, arquivo, indent=2, ensure_ascii=False, default=str)
        os.replace(nome_tmp, caminho)
    finally:
        if nome_tmp and os.path.exists(nome_tmp):
            os.unlink(nome_tmp)


def gravar_relatorio(dados):
    # Um backup da versão anterior do relatório, preservado apenas na primeira atualização.
    backup = RELATORIO.with_name("relatorio_antes_integracao.json")
    if RELATORIO.exists() and not backup.exists():
        shutil.copy2(RELATORIO, backup)
    dados = {**dados, "gerado_em": datetime.now().isoformat(timespec="seconds")}
    salvar_json_arquivo(RELATORIO, dados)
    return dados


class EnviarLogBody(BaseModel):
    arquivo: str
    conteudo: str


@router.post("/logs/enviar")
def enviar_log(corpo: EnviarLogBody, usuario: str = Depends(exigir_admin)):
    """Substitui um dos logs permitidos com backup; não aceita caminhos arbitrários."""
    permitidos = {"auth.log", "firewall.log", "web_access.log"}
    if corpo.arquivo not in permitidos:
        raise HTTPException(422, "Nome inválido: escolha auth.log, firewall.log ou web_access.log.")
    if not corpo.conteudo.strip():
        raise HTTPException(422, "Arquivo vazio.")
    if len(corpo.conteudo.encode("utf-8")) > 1_000_000:
        raise HTTPException(413, "Arquivo muito grande. Limite: 1 MB.")
    if "\x00" in corpo.conteudo:
        raise HTTPException(422, "O arquivo deve conter texto, não dados binários.")
    destino = LOGS / corpo.arquivo
    with LOCK:
        if destino.exists():
            arquivo_backup = BACKEND / "dados" / "backups_logs" / corpo.arquivo
            arquivo_backup.parent.mkdir(parents=True, exist_ok=True)
            if not arquivo_backup.exists():
                shutil.copy2(destino, arquivo_backup)
        # Backup do original garantido antes da substituição.
        salvar_texto_arquivo(destino, corpo.conteudo)
    return {"mensagem": f"{corpo.arquivo} enviado. Agora execute Processar logs."}


def salvar_texto_arquivo(caminho: Path, texto: str):
    caminho.parent.mkdir(parents=True, exist_ok=True)
    nome_tmp = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=caminho.parent,
            prefix=".viotrace-", suffix=".tmp", delete=False
        ) as arquivo:
            nome_tmp = arquivo.name
            arquivo.write(texto)
        os.replace(nome_tmp, caminho)
    finally:
        if nome_tmp and os.path.exists(nome_tmp):
            os.unlink(nome_tmp)


class ProcessarBody(BaseModel):
    enriquecer: bool = False


@router.post("/processar")
def processar(corpo: ProcessarBody, usuario: str = Depends(exigir_admin)):
    """Lê logs fixos do projeto, aplica regras e detecta anomalias."""
    if not LOGS.is_dir() or not CONFIG.is_file():
        raise HTTPException(503, "Pasta logs/ ou config/regras.json ausente em securaPy.")
    with LOCK:
        eventos = carregar_todos_os_logs(str(LOGS))
        if not eventos:
            raise HTTPException(422, "Nenhum evento válido encontrado nos arquivos de log.")
        regras = carregar_regras(str(CONFIG))
        alertas = aplicar_regras(eventos, regras)
        brute = detectar_brute_force(eventos)
        scan = detectar_port_scan(eventos)
        blacklist = verificar_blacklist(eventos, BLACKLIST)
        ameacas = gerar_resumo_ameacas(brute, scan, blacklist)
        if corpo.enriquecer and alertas:
            alertas = enriquecer_alertas(alertas, {})
        dados = gravar_relatorio({
            "origem": "processamento_local_dos_logs",
            "total_eventos": len(eventos),
            "total_alertas": len(alertas),
            "eventos": eventos,
            "alertas": alertas,
            "resumo_ameacas": ameacas,
            "deteccoes": {
                "brute_force": brute,
                "port_scan": scan,
                "ips_blacklist": sorted(blacklist[0]),
                "contagem_blacklist": blacklist[1],
            },
            "fontes": dict(Counter(e.get("fonte", "-") for e in eventos)),
            "regras_ativas": len(regras),
        })
    return {
        "mensagem": "Logs processados. Dashboard e IA podem usar o relatório atualizado.",
        "total_eventos": dados["total_eventos"],
        "total_alertas": dados["total_alertas"],
        "ips_suspeitos": len(dados["resumo_ameacas"]),
        "gerado_em": dados["gerado_em"],
    }


@router.post("/enriquecer")
def enriquecer(usuario: str = Depends(exigir_admin)):
    """Consulta IPinfo para IPs encontrados em alertas; erros são marcados nos próprios dados."""
    with LOCK:
        dados = ler_relatorio()
        if not dados["alertas"]:
            raise HTTPException(409, "Não há alertas para enriquecer.")
        cache = {}
        dados["alertas"] = enriquecer_alertas(dados["alertas"], cache)
        gravar_relatorio(dados)
    return {"mensagem": "Enriquecimento finalizado.", "ips_consultados": len(cache)}


@router.get("/resumo")
def resumo(usuario: str = Depends(exigir_usuario)):
    dados = ler_relatorio()
    eventos = dados.get("eventos", [])
    return {
        "gerado_em": dados.get("gerado_em"),
        "origem": dados.get("origem", "relatorio_historico"),
        "total_eventos": dados.get("total_eventos", len(eventos)),
        "total_alertas": dados.get("total_alertas", len(dados["alertas"])),
        "por_fonte": dict(Counter(e.get("fonte", "-") for e in eventos)),
        "por_severidade": dict(Counter(a.get("severidade", "INFO") for a in dados["alertas"])),
        "resumo_ameacas": dados.get("resumo_ameacas", []),
        "deteccoes": dados.get("deteccoes", {}),
    }


@router.get("/eventos")
def consultar_eventos(
    fonte: str | None = Query(None, pattern="^(auth|firewall|web)$"),
    tipo: str | None = Query(None, max_length=30),
    ip: str | None = Query(None, max_length=45),
    limite: int = Query(200, ge=1, le=5000),
    usuario: str = Depends(exigir_usuario),
):
    eventos = ler_relatorio().get("eventos", [])
    filtrados = filtrar_eventos(eventos, fonte=fonte, tipo=tipo or None, ip=ip or None)
    return {"total": len(filtrados), "eventos": filtrados[:limite], "limitado": len(filtrados) > limite}


@router.get("/top-ips")
def consultar_top_ips(usuario: str = Depends(exigir_usuario)):
    dados = ler_relatorio()
    eventos = dados.get("eventos", [])
    origem = "eventos" if eventos else "alertas"
    fonte = eventos if eventos else dados["alertas"]
    ranking = Counter(e.get("ip") for e in fonte if e.get("ip")).most_common(10)
    return {"origem": origem, "ips": [{"ip": ip, "quantidade": n} for ip, n in ranking]}


@router.get("/ip/{ip}")
def consultar_ip(ip: str, usuario: str = Depends(exigir_usuario)):
    try:
        ip_address(ip)
    except ValueError:
        raise HTTPException(422, "Endereço IP inválido.")
    dados = ler_relatorio()
    eventos = [e for e in dados.get("eventos", []) if e.get("ip") == ip]
    alertas = [a for a in dados["alertas"] if a.get("ip") == ip]
    if not eventos and not alertas:
        raise HTTPException(404, "IP não encontrado no relatório.")
    geo = next((a.get("geolocalizacao") for a in alertas if a.get("geolocalizacao")), None)
    return {"ip": ip, "eventos": eventos, "alertas": alertas, "geolocalizacao": geo}


@router.get("/regras")
def consultar_regras(usuario: str = Depends(exigir_usuario)):
    try:
        dados = json.loads(CONFIG.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise HTTPException(503, "Configuração de regras indisponível.")
    regras = dados.get("regras", []) if isinstance(dados, dict) else dados
    return {"regras": regras}


class AtualizarRegra(BaseModel):
    ativa: bool


@router.patch("/regras/{id_regra}")
def alterar_regra(id_regra: str, corpo: AtualizarRegra, usuario: str = Depends(exigir_admin)):
    if len(id_regra) > 20:
        raise HTTPException(422, "ID de regra inválido.")
    with LOCK:
        try:
            config = json.loads(CONFIG.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise HTTPException(503, "Arquivo de regras indisponível.")
        regras = config.get("regras", []) if isinstance(config, dict) else config
        regra = next((r for r in regras if r.get("id") == id_regra), None)
        if regra is None:
            raise HTTPException(404, "Regra não encontrada.")
        regra["ativa"] = corpo.ativa
        backup = CONFIG.with_name("regras.antes_integracao.json")
        if not backup.exists():
            shutil.copy2(CONFIG, backup)
        salvar_json_arquivo(CONFIG, config)
    return {"mensagem": "Regra atualizada. Processe os logs para aplicar a alteração.", "id": id_regra, "ativa": corpo.ativa}


@router.get("/exportar")
def exportar(usuario: str = Depends(exigir_usuario)):
    dados = ler_relatorio()
    nome = f"viotrace_relatorio_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    corpo = json.dumps(dados, indent=2, ensure_ascii=False, default=str).encode("utf-8")
    return Response(content=corpo, media_type="application/json", headers={
        "Content-Disposition": f'attachment; filename="{nome}"',
        "Cache-Control": "no-store",
    })


@router.get("/tcp/status")
def status_tcp(usuario: str = Depends(exigir_usuario)):
    with tcp.lock:
        conectados = len(tcp.clientes)
    return {
        "servidor_iniciado_pelo_vio": bool(TCP_THREAD and TCP_THREAD.is_alive()),
        "clientes_conectados": conectados,
        "alertas_transmitidos_na_sessao": len(tcp.historico_alertas),
        "porta": 9999,
        "host": "127.0.0.1",
    }


@router.post("/tcp/iniciar")
def iniciar_tcp(usuario: str = Depends(exigir_admin)):
    global TCP_THREAD
    with LOCK:
        if TCP_THREAD and TCP_THREAD.is_alive():
            return {"mensagem": "Servidor TCP já foi iniciado."}
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if sock.connect_ex(("127.0.0.1", 9999)) == 0:
                raise HTTPException(409, "Porta 9999 já ocupada por outro processo.")
        TCP_THREAD = threading.Thread(
            target=tcp.iniciar_servidor,
            args=("127.0.0.1", 9999),
            daemon=True,
            name="viotrace-tcp",
        )
        TCP_THREAD.start()
    return {"mensagem": "Servidor TCP iniciado em 127.0.0.1:9999. Conecte clientes locais."}


@router.post("/tcp/transmitir")
def transmitir_tcp(usuario: str = Depends(exigir_admin)):
    if not TCP_THREAD or not TCP_THREAD.is_alive():
        raise HTTPException(409, "Inicie o servidor TCP primeiro.")
    alertas = ler_relatorio()["alertas"]
    if not alertas:
        raise HTTPException(409, "Nenhum alerta disponível.")
    with LOCK:
        for alerta in alertas:
            tcp.broadcast_alerta(alerta)
    return {"mensagem": "Alertas retransmitidos aos clientes TCP conectados.", "quantidade": len(alertas)}


@router.get("/tcp/historico")
def historico_tcp(usuario: str = Depends(exigir_usuario)):
    return {"historico": tcp.historico_alertas[-30:]}
