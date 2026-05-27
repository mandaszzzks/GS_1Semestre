"""
Modulo 4a - Servidor de Alertas em Tempo Real
Servidor TCP que aceita conexoes de multiplos clientes (consoles de monitoramento)
e faz broadcast de alertas de seguranca para todos os clientes conectados.

Comandos suportados pelo cliente:
    /status    - mostra quantos clientes conectados e alertas na sessao
    /historico - envia os ultimos 10 alertas
    /sair      - desconecta do servidor
"""

import socket
import threading
from datetime import datetime

# Configuracao
HOST = "0.0.0.0"
PORTA = 9999
MAX_CLIENTES = 10

# Estado global do servidor
clientes = {}           # {conexao: endereco}
lock = threading.Lock()
historico_alertas = []  # ultimos alertas formatados


def formatar_alerta(alerta_dict):
    """
    Converte um dicionario de alerta em string formatada para exibicao.

    Parametros:
        alerta_dict (dict): alerta com chaves timestamp, severidade,
                            regra_nome, ip, descricao

    Retorna:
        str: alerta formatado, ex:
        "[08:15:01] [CRITICA] Brute Force - 185.220.101.1 - 10 tentativas de login"
    """
    timestamp = alerta_dict.get("timestamp", "")
    # Extrai apenas a hora (HH:MM:SS) do timestamp "YYYY-MM-DD HH:MM:SS"
    hora = timestamp.split(" ")[-1] if " " in timestamp else timestamp

    severidade = alerta_dict.get("severidade", "INFO")
    regra_nome = alerta_dict.get("regra_nome", "Alerta")
    ip = alerta_dict.get("ip", "N/A")
    descricao = alerta_dict.get("descricao", "")

    return f"[{hora}] [{severidade}] {regra_nome} - {ip} - {descricao}"


def broadcast_alerta(alerta):
    """
    Envia um alerta para todos os clientes conectados.

    Parametros:
        alerta (dict ou str): alerta a ser enviado
    """
    global historico_alertas

    # Formata se for dicionario
    if isinstance(alerta, dict):
        mensagem = formatar_alerta(alerta)
    else:
        mensagem = str(alerta)

    # Adiciona ao historico
    historico_alertas.append(mensagem)

    # Envia para todos os clientes
    clientes_para_remover = []
    with lock:
        conexoes = list(clientes.keys())

    for conexao in conexoes:
        try:
            conexao.send((mensagem + "\n").encode())
        except (ConnectionResetError, BrokenPipeError, OSError):
            clientes_para_remover.append(conexao)

    for conexao in clientes_para_remover:
        remover_cliente(conexao)

    if conexoes:
        print(f"[BROADCAST] Alerta enviado para {len(conexoes)} cliente(s): {mensagem}")


def remover_cliente(conexao):
    """
    Remove um cliente da lista de conectados.

    Parametros:
        conexao: objeto socket do cliente
    """
    with lock:
        endereco = clientes.pop(conexao, None)

    if endereco:
        print(f"[SERVIDOR] Cliente desconectado: {endereco[0]}:{endereco[1]}")

    try:
        conexao.close()
    except OSError:
        pass  # Ja estava fechado


def tratar_cliente(conexao, endereco):
    """
    Gerencia a comunicacao com um cliente individual.
    Esta funcao roda em uma thread separada para cada cliente.

    Parametros:
        conexao: objeto socket do cliente
        endereco: tupla (ip, porta) do cliente
    """
    # Registra o cliente
    with lock:
        clientes[conexao] = endereco

    print(f"[SERVIDOR] Cliente conectado: {endereco[0]}:{endereco[1]}")

    # Mensagem de boas-vindas
    boas_vindas = (
        "=== SecuraPy SIEM - Console de Alertas ===\n"
        f"Conectado em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        "Comandos disponiveis: /status, /historico, /sair\n"
        "------------------------------------------\n"
    )
    try:
        conexao.send(boas_vindas.encode())
    except (ConnectionResetError, BrokenPipeError, OSError):
        remover_cliente(conexao)
        return

    # Loop principal - recebe comandos do cliente
    try:
        while True:
            dados = conexao.recv(1024).decode("utf-8", errors="replace").strip()

            if not dados:
                # Cliente fechou a conexao
                break

            if dados == "/sair":
                try:
                    conexao.send("Ate logo! Desconectando...\n".encode())
                except OSError:
                    pass
                break

            elif dados == "/status":
                with lock:
                    total_clientes = len(clientes)
                total_alertas = len(historico_alertas)
                resposta = (
                    f"Clientes conectados: {total_clientes} | "
                    f"Alertas na sessao: {total_alertas}\n"
                )
                conexao.send(resposta.encode())

            elif dados == "/historico":
                ultimos = historico_alertas[-10:]  # ultimos 10
                if ultimos:
                    resposta = "--- Ultimos alertas ---\n" + "\n".join(ultimos) + "\n-----------------------\n"
                else:
                    resposta = "Nenhum alerta registrado ainda.\n"
                conexao.send(resposta.encode())

            else:
                # Comando desconhecido
                conexao.send(f"Comando desconhecido: '{dados}'. Use /status, /historico ou /sair\n".encode())

    except (ConnectionResetError, BrokenPipeError, OSError):
        pass  # Desconexao inesperada - tratada abaixo

    finally:
        remover_cliente(conexao)


def iniciar_servidor(host=HOST, porta=PORTA):
    """
    Inicia o servidor TCP de alertas.

    Parametros:
        host (str): endereco para bind (padrao: "0.0.0.0")
        porta (int): porta para bind (padrao: 9999)
    """
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Permite reusar a porta imediatamente apos encerrar o servidor
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        servidor.bind((host, porta))
        servidor.listen(MAX_CLIENTES)
        print("=== Servidor de Alertas SecuraPy ===")
        print(f"Rodando em {host}:{porta}")
        print("Aguardando conexoes... (Ctrl+C para encerrar)\n")

        while True:
            try:
                conexao, endereco = servidor.accept()
                thread = threading.Thread(
                    target=tratar_cliente,
                    args=(conexao, endereco),
                    daemon=True  # Encerra junto com o programa principal
                )
                thread.start()
            except OSError:
                # Servidor foi fechado (Ctrl+C)
                break

    except KeyboardInterrupt:
        print("\n[SERVIDOR] Encerrando servidor...")
    finally:
        servidor.close()
        print("[SERVIDOR] Servidor encerrado.")


if __name__ == "__main__":
    iniciar_servidor()