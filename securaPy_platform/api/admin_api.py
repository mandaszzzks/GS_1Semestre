"""Operações administrativas VioTrace UX 2.0.

Reutiliza as credenciais e o armazenamento já existentes em seguranca.py.
Não expõe hashes de senha nem os códigos completos dos convites.
"""
import hmac
import re
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from seguranca import (
    ARQUIVO_CONTAS,
    ARQUIVO_CONVITES,
    LOCK,
    exigir_usuario,
    ler_json_cadastro,
    ler_usuario,
    salvar_json_cadastro,
)

router_admin = APIRouter(prefix="/api/admin", tags=["Administração"])


def exigir_admin(usuario: str = Depends(exigir_usuario)):
    admin = ler_usuario().get("usuario", "")
    if not hmac.compare_digest(usuario.casefold(), str(admin).casefold()):
        raise HTTPException(status_code=403, detail="Acesso reservado ao administrador.")
    return usuario


class EstadoUsuario(BaseModel):
    ativo: bool


@router_admin.get("/usuarios")
def listar_usuarios(_admin: str = Depends(exigir_admin)):
    with LOCK:
        contas = ler_json_cadastro(ARQUIVO_CONTAS)
        principal = ler_usuario().get("usuario", "administrador")
        pessoas = [{"usuario": principal, "papel": "admin", "ativo": True}]
        for registro in contas.values():
            if not isinstance(registro, dict) or not isinstance(registro.get("usuario"), str):
                continue
            pessoas.append({
                "usuario": registro["usuario"],
                "papel": "analista",
                "ativo": registro.get("ativo", True) is not False,
            })
    return {"usuarios": sorted(pessoas, key=lambda p: (p["papel"] != "admin", p["usuario"].casefold()))}


@router_admin.patch("/usuarios/{usuario}/status")
def alterar_status_usuario(usuario: str, corpo: EstadoUsuario, _admin: str = Depends(exigir_admin)):
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,32}", usuario):
        raise HTTPException(status_code=422, detail="Nome de usuário inválido.")
    if usuario.casefold() == str(ler_usuario().get("usuario", "")).casefold():
        raise HTTPException(status_code=403, detail="A conta administradora não pode ser suspensa.")

    with LOCK:
        contas = ler_json_cadastro(ARQUIVO_CONTAS)
        conta = contas.get(usuario.casefold())
        if not isinstance(conta, dict):
            raise HTTPException(status_code=404, detail="Usuário não encontrado.")
        conta["ativo"] = corpo.ativo
        salvar_json_cadastro(ARQUIVO_CONTAS, contas)
    return {"usuario": conta["usuario"], "ativo": corpo.ativo, "mensagem": "Permissão atualizada."}


@router_admin.get("/convites")
def listar_convites(_admin: str = Depends(exigir_admin)):
    agora = time.time()
    with LOCK:
        convites = ler_json_cadastro(ARQUIVO_CONVITES)
        pendentes = [
            {"id": codigo_hash, "expira_em": expiracao}
            for codigo_hash, expiracao in convites.items()
            if re.fullmatch(r"[0-9a-f]{64}", codigo_hash)
            and isinstance(expiracao, (int, float))
            and expiracao > agora
        ]
    pendentes.sort(key=lambda c: c["expira_em"])
    return {"convites": pendentes}


@router_admin.delete("/convites/{codigo_hash}")
def revogar_convite(codigo_hash: str, _admin: str = Depends(exigir_admin)):
    if not re.fullmatch(r"[0-9a-f]{64}", codigo_hash):
        raise HTTPException(status_code=422, detail="Identificador de convite inválido.")
    with LOCK:
        convites = ler_json_cadastro(ARQUIVO_CONVITES)
        if codigo_hash not in convites:
            raise HTTPException(status_code=404, detail="Convite não encontrado ou já utilizado.")
        del convites[codigo_hash]
        salvar_json_cadastro(ARQUIVO_CONVITES, convites)
    return {"mensagem": "Convite revogado."}
