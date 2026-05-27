"""
Modulo 4b - Cliente de Alertas
Conecta ao servidor de alertas e recebe notificacoes em tempo real.
Permite enviar comandos: /status, /historico, /sair
"""

import socket
import threading

HOST = "127.0.0.1"
PORTA = 9999


def receber_alertas(cliente):
    """
    Thread que fica ouvindo mensagens do servidor e exibindo no terminal.

    Parametros:
        cliente: objeto socket conectado ao servidor
    """
    while True:
        try:
            dados = cliente.recv(4096).decode("utf-8", errors="replace")
            if not dados:
                # Servidor encerrou a conexao
                print("\n[CLIENTE] Servidor desconectou.")
                break
            # Exibe a mensagem recebida (sem adicionar \n extra se ja tiver)
            print(dados, end="", flush=True)
        except (ConnectionResetError, BrokenPipeError, OSError):
            print("\n[CLIENTE] Conexao encerrada.")
            break


def conectar_servidor(host=HOST, porta=PORTA):
    """
    Conecta ao servidor de alertas e inicia a interacao.

    Parametros:
        host (str): endereco do servidor
        porta (int): porta do servidor
    """
    try:
        cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cliente.connect((host, porta))
        print(f"Conectado ao SecuraPy SIEM ({host}:{porta})")
        print("Comandos: /status, /historico, /sair\n")

        # Thread de recepcao (daemon - encerra com o programa)
        thread = threading.Thread(
            target=receber_alertas,
            args=(cliente,),
            daemon=True
        )
        thread.start()

        # Loop principal - le comandos do usuario e envia ao servidor
        while True:
            try:
                comando = input(">> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[CLIENTE] Encerrando...")
                break

            if not comando:
                continue

            try:
                cliente.send((comando + "\n").encode())
            except (ConnectionResetError, BrokenPipeError, OSError):
                print("[CLIENTE] Erro ao enviar comando. Conexao perdida.")
                break

            if comando == "/sair":
                break

    except ConnectionRefusedError:
        print(f"[ERRO] Nao foi possivel conectar em {host}:{porta}.")
        print("Verifique se o servidor esta rodando (python servidor_alertas.py).")
    except OSError as e:
        print(f"[ERRO] Falha de conexao: {e}")
    finally:
        try:
            cliente.close()
        except OSError:
            pass
        print("[CLIENTE] Desconectado.")


if __name__ == "__main__":
    conectar_servidor()