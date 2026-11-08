"""Autenticação local do VioTrace: token em memória, hash PBKDF2 e relatório privado."""
import hashlib
import hmac
import json
import secrets
import threading
import time
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

PASTA = Path(__file__).resolve().parent
ARQUIVO_USUARIO = PASTA / "credenciais.json"
ARQUIVO_RELATORIO = PASTA / "dados" / "relatorio.json"
SESSOES = {}
FALHAS = {}
LOCK = threading.Lock()
DURACAO_SESSAO = 8 * 60 * 60

router = APIRouter(prefix="/api")

class Login(BaseModel):
    usuario: str = Field(min_length=1, max_length=40)
    senha: str = Field(min_length=1, max_length=256)

def ler_usuario():
    try:
        return json.loads(ARQUIVO_USUARIO.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise HTTPException(503, "Usuário não configurado. Execute: py instalar_login.py")

def validar_senha(senha, registro):
    try:
        if registro.get("ativo", True) is False:
            return False
        sal = bytes.fromhex(registro["sal"])
        esperado = bytes.fromhex(registro["hash"])
        obtido = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), sal, 600_000)
        return hmac.compare_digest(obtido, esperado)
    except (ValueError, KeyError, TypeError):
        return False

def exigir_usuario(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Faça login para acessar o VioTrace.")
    token = authorization.removeprefix("Bearer ").strip()
    with LOCK:
        sessao = SESSOES.get(token)
        if sessao and sessao[1] <= time.time():
            SESSOES.pop(token, None)
            sessao = None
    if not sessao:
        raise HTTPException(401, "Sessão inválida ou expirada. Entre novamente.")
    nome = sessao[0]
    principal = str(ler_usuario().get("usuario", ""))
    if nome.casefold() != principal.casefold():
        conta = ler_usuarios_cadastro().get(nome.casefold())
        if not isinstance(conta, dict) or conta.get("ativo", True) is False:
            with LOCK:
                SESSOES.pop(token, None)
            raise HTTPException(401, "Conta suspensa ou removida. Contate o administrador.")
    return nome

@router.post("/login")
def login(corpo: Login, request: Request):
    endereco = request.client.host if request.client else "local"
    agora = time.time()
    with LOCK:
        anteriores = [t for t in FALHAS.get(endereco, []) if agora - t < 300]
        FALHAS[endereco] = anteriores
        if len(anteriores) >= 5:
            raise HTTPException(429, "Muitas tentativas. Aguarde cinco minutos.")
    administrador = ler_usuario()
    if hmac.compare_digest(
        corpo.usuario.casefold(),
        administrador.get("usuario", "").casefold()
    ):
        registro = administrador
        papel = "admin"
    else:
        registro = ler_usuarios_cadastro().get(
            corpo.usuario.casefold()
        )
        papel = "analista"

    ok_usuario = registro is not None
    ok_senha = validar_senha(corpo.senha, registro or {})

    if not (ok_usuario and ok_senha):
        with LOCK:
            FALHAS.setdefault(endereco, []).append(agora)
        raise HTTPException(401, "Usuário ou senha inválidos.")
    token = secrets.token_urlsafe(40)
    with LOCK:
        FALHAS.pop(endereco, None)
        SESSOES[token] = (registro["usuario"], agora + DURACAO_SESSAO)
    return {"token": token, "usuario": registro["usuario"], "papel": papel, "expira_em_segundos": DURACAO_SESSAO}

@router.get("/sessao")
def sessao(usuario: str = Depends(exigir_usuario)):
    return {"autenticado": True, "usuario": usuario}

@router.post("/logout")
def logout(authorization: str | None = Header(default=None)):
    if authorization and authorization.startswith("Bearer "):
        with LOCK:
            SESSOES.pop(authorization.removeprefix("Bearer ").strip(), None)
    return {"mensagem": "Sessão encerrada."}

@router.get("/relatorio")
def relatorio(usuario: str = Depends(exigir_usuario)):
    try:
        dados = json.loads(ARQUIVO_RELATORIO.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise HTTPException(503, "Relatório não encontrado no backend/dados.")
    if not isinstance(dados, dict) or not isinstance(dados.get("alertas"), list):
        raise HTTPException(503, "Relatório inválido.")
    return dados


# CADASTRO_POR_CONVITE_V1
import os
import re
import tempfile

ARQUIVO_CONTAS = PASTA / "usuarios.json"
ARQUIVO_CONVITES = PASTA / "convites.json"
FALHAS_CADASTRO = {}

class NovoCadastro(BaseModel):
    usuario: str = Field(min_length=3, max_length=32)
    senha: str = Field(min_length=12, max_length=128)
    convite: str = Field(min_length=15, max_length=100)

def ler_json_cadastro(caminho):
    if not caminho.exists():
        return {}
    try:
        dados = json.loads(caminho.read_text(encoding="utf-8"))
        if not isinstance(dados, dict):
            raise ValueError("formato")
        return dados
    except (OSError, ValueError):
        raise HTTPException(
            503, "Erro no armazenamento de usuarios."
        )

def salvar_json_cadastro(caminho, dados):
    temporario = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8",
            dir=caminho.parent,
            prefix=".viotrace-",
            suffix=".tmp",
            delete=False
        ) as arquivo:
            temporario = arquivo.name
            json.dump(dados, arquivo, ensure_ascii=False, indent=2)
        os.replace(temporario, caminho)
    finally:
        if temporario and os.path.exists(temporario):
            os.unlink(temporario)

def ler_usuarios_cadastro():
    return ler_json_cadastro(ARQUIVO_CONTAS)

@router.post("/convites")
def criar_convite(usuario: str = Depends(exigir_usuario)):
    admin = ler_usuario().get("usuario", "")

    if not hmac.compare_digest(usuario, admin):
        raise HTTPException(
            403, "Apenas o administrador pode gerar convites."
        )

    agora = time.time()
    with LOCK:
        convites = {
            k: v
            for k, v in ler_json_cadastro(ARQUIVO_CONVITES).items()
            if isinstance(v, (int, float)) and v > agora
        }

        if len(convites) >= 20:
            raise HTTPException(
                429, "Limite de convites ativos atingido."
            )

        codigo = secrets.token_urlsafe(24)
        codigo_hash = hashlib.sha256(
            codigo.encode()
        ).hexdigest()

        convites[codigo_hash] = agora + 24 * 3600

        salvar_json_cadastro(ARQUIVO_CONVITES, convites)

    return {
        "convite": codigo,
        "validade_horas": 24,
        "uso_unico": True
    }

@router.post("/cadastro", status_code=201)
def cadastrar(corpo: NovoCadastro, request: Request):
    nome = corpo.usuario.strip()

    if not re.fullmatch(r"[A-Za-z0-9._-]{3,32}", nome):
        raise HTTPException(
            422, "Nome de usuario invalido."
        )

    endereco = request.client.host if request.client else "local"
    agora = time.time()

    with LOCK:
        tentativas = [
            t for t in FALHAS_CADASTRO.get(endereco, [])
            if agora - t < 300
        ]

        FALHAS_CADASTRO[endereco] = tentativas

        if len(tentativas) >= 5:
            raise HTTPException(
                429, "Muitas tentativas. Aguarde cinco minutos."
            )

        contas = ler_usuarios_cadastro()
        administrador = ler_usuario().get(
            "usuario", ""
        ).casefold()

        if nome.casefold() in contas or nome.casefold() == administrador:
            raise HTTPException(
                409, "Esse usuario ja existe."
            )

        convites = ler_json_cadastro(ARQUIVO_CONVITES)

        codigo_hash = hashlib.sha256(
            corpo.convite.strip().encode()
        ).hexdigest()

        expira = convites.get(codigo_hash, 0)

        if not isinstance(expira, (int, float)) or expira <= agora:
            FALHAS_CADASTRO[endereco].append(agora)
            raise HTTPException(
                403, "Convite invalido, expirado ou utilizado."
            )

        if len(contas) >= 100:
            raise HTTPException(429, "Limite de usuarios atingido.")

        sal = secrets.token_bytes(16)

        digest = hashlib.pbkdf2_hmac(
            "sha256",
            corpo.senha.encode(),
            sal,
            600_000
        )

        contas[nome.casefold()] = {
            "usuario": nome,
            "sal": sal.hex(),
            "hash": digest.hex()
        }

        salvar_json_cadastro(ARQUIVO_CONTAS, contas)

        del convites[codigo_hash]
        salvar_json_cadastro(ARQUIVO_CONVITES, convites)

        FALHAS_CADASTRO.pop(endereco, None)

    return {
        "mensagem": "Conta criada! Entre com seu usuario e senha."
    }

# VIOTRACE_UX2_ACTIVE_USERS
