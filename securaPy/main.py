"""
SecuraPy SIEM - Ponto de Entrada Principal
Integra todos os modulos: coletor, regras, detector, enriquecimento,
servidor de alertas e relatorios em um menu interativo.
"""

# Configuracoes
PASTA_LOGS = "logs"
ARQUIVO_REGRAS = "config/regras.json"
BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}


def main():
    """
    Funcao principal que roda o loop do menu interativo.

    Fluxo esperado:
        1. Opcao 1: Carregar logs -> aplicar regras -> detectar anomalias
        2. Opcao 2-7: Consultar e visualizar resultados
        3. Opcao 8: Exportar relatorio
        4. Opcao 9: Iniciar servidor de alertas
        5. Opcao 0: Sair

    Variaveis que devem ser mantidas entre as opcoes:
        - eventos: lista de todos os eventos carregados
        - alertas: lista de alertas das regras
        - resumo: resumo de ameacas do detector
        - cache_enriquecimento: cache de consultas de IP

    Dicas:
        - Inicialize as variaveis como listas/dicts vazios antes do loop
        - Na opcao 1, chame os modulos em sequencia:
          1. carregar_todos_os_logs(PASTA_LOGS)
          2. carregar_regras(ARQUIVO_REGRAS)
          3. aplicar_regras(eventos, regras)
          4. detectar_brute_force(eventos)
          5. detectar_port_scan(eventos)
          6. verificar_blacklist(eventos, BLACKLIST)
          7. gerar_resumo_ameacas(brute, scan, blacklist_res)
        - Nas opcoes 2-8, verifique se os dados ja foram carregados
          (if not eventos: print("Carregue os logs primeiro (opcao 1)"))
    """
    eventos = []
    alertas = []
    resumo = []
    cache_enriquecimento = {}

    print("=" * 50)
    print("       SecuraPy SIEM - Coding for Security")
    print("=" * 50)

    while True:
        opcao = exibir_menu()

        if opcao == 1:
            # TODO: Carregar e processar logs
            # 1. eventos = carregar_todos_os_logs(PASTA_LOGS)
            # 2. regras = carregar_regras(ARQUIVO_REGRAS)
            # 3. alertas = aplicar_regras(eventos, regras)
            # 4. brute = detectar_brute_force(eventos)
            # 5. scan = detectar_port_scan(eventos)
            # 6. bl = verificar_blacklist(eventos, BLACKLIST)
            # 7. resumo = gerar_resumo_ameacas(brute, scan, bl)
            pass

        elif opcao == 2:
            # TODO: Resumo geral
            # resumo_geral(eventos, alertas)
            pass

        elif opcao == 3:
            # TODO: Filtrar eventos
            # Pedir ao usuario: fonte, tipo e/ou ip
            # resultado = filtrar_eventos(eventos, fonte, tipo, ip)
            pass

        elif opcao == 4:
            # TODO: Buscar IP
            # ip = input("Digite o IP: ")
            # buscar_ip(ip, eventos, alertas, cache_enriquecimento)
            pass

        elif opcao == 5:
            # TODO: Top 10 IPs suspeitos
            # resultado = top_ips(eventos)
            pass

        elif opcao == 6:
            # TODO: Ver alertas por severidade
            # Pedir severidade ao usuario e filtrar
            pass

        elif opcao == 7:
            # TODO: Enriquecer IPs suspeitos
            # alertas = enriquecer_alertas(alertas, cache_enriquecimento)
            pass

        elif opcao == 8:
            # TODO: Exportar relatorio JSON
            # exportar_relatorio_json(dados, caminho)
            pass

        elif opcao == 9:
            # TODO: Iniciar servidor de alertas
            # from servidor_alertas import iniciar_servidor
            # iniciar_servidor()
            pass

        elif opcao == 0:
            print("Encerrando SecuraPy. Ate logo!")
            break

        else:
            print("Opcao invalida. Tente novamente.")


if __name__ == "__main__":
    main()
