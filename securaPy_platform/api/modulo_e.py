"""Módulo E: headers defensivos, trilha de acessos e teste de saída XSS.

O React já renderiza conteúdos como texto. Este módulo também oferece uma
rota HTML de laboratório com html.escape para demonstrar E1 de modo isolado.
"""
from __future__ import annotations

import html
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from time import perf_counter
from datetime import datetime, timezone
from threading import Lock
from itertools import count

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from seguranca import exigir_usuario

ROUTER_E = APIRouter(prefix="/api/modulo-e", tags=["Segurança Web - Laboratório E1"])
DEMO_ALERTAS: list[dict] = []
_DEMO_LOCK = Lock()
_PROXIMO_ID = count(1)

HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'none'; object-src 'none'"
    ),
}


class NovoAlertaDemo(BaseModel):
    descricao: str = Field(min_length=1, max_length=350)
    severidade: str = Field(default="BAIXA", pattern="^(BAIXA|MEDIA|ALTA|CRITICA)$")


@ROUTER_E.post("/alertas", status_code=201)
def criar_alerta_demo(corpo: NovoAlertaDemo, _usuario: str = Depends(exigir_usuario)):
    """Alerta somente de demonstração, não altera o relatório do SecuraPy."""
    with _DEMO_LOCK:
        novo = {"id": next(_PROXIMO_ID), "descricao": corpo.descricao, "severidade": corpo.severidade}
        if len(DEMO_ALERTAS) >= 30:
            DEMO_ALERTAS.pop(0)
        DEMO_ALERTAS.append(novo)
    return novo


@ROUTER_E.get("/alertas")
def listar_alertas_demo(_usuario: str = Depends(exigir_usuario)):
    with _DEMO_LOCK:
        return {"alertas": list(DEMO_ALERTAS)}


@ROUTER_E.get("/alertas/html", response_class=HTMLResponse)
def listar_alertas_demo_html(_usuario: str = Depends(exigir_usuario)):
    """Renderização HTML intencional para demonstrar escape da entrada XSS."""
    with _DEMO_LOCK:
        linhas = "\n".join(
            "<li><strong>" + html.escape(a["severidade"], quote=True)
            + "</strong>: " + html.escape(a["descricao"], quote=True) + "</li>"
            for a in DEMO_ALERTAS
        )
    return HTMLResponse("<!doctype html><html lang='pt-BR'><head><meta charset='utf-8'>"
                        "<title>VioTrace - Teste XSS</title></head><body>"
                        "<h1>Alertas de laboratório (texto escapado)</h1><ul>"
                        + linhas + "</ul></body></html>")


def instalar_protecao_web(app, arquivo_log: Path | None = None):
    """Acrescenta os três headers e auditoria de método/rota/status (sem segredos)."""
    pasta = Path(__file__).resolve().parent / "dados"
    caminho = Path(arquivo_log) if arquivo_log else pasta / "auditoria_acesso.log"
    caminho.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("viotrace.acesso." + str(caminho))
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        logger.addHandler(RotatingFileHandler(caminho, maxBytes=1_000_000, backupCount=2, encoding="utf-8"))

    @app.middleware("http")
    async def protecoes_e_auditoria(request: Request, call_next):
        inicio = perf_counter()
        try:
            resposta = await call_next(request)
        except Exception:
            # Evita expor traceback/dados internos em respostas HTTP 500.
            resposta = JSONResponse({"detail": "Erro interno do servidor."}, status_code=500)
        resposta.headers.update(HEADERS)
        if request.url.path.startswith("/api/"):
            resposta.headers["Cache-Control"] = "no-store"
        registro = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metodo": request.method,
            # Sem query string, Authorization, cookies ou corpo da requisição.
            "caminho": request.url.path[:250].replace("\r", "").replace("\n", ""),
            "status": resposta.status_code,
            "duracao_ms": round((perf_counter() - inicio) * 1000, 1),
        }
        logger.info(json.dumps(registro, ensure_ascii=False))
        return resposta

    return caminho
