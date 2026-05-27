# SecuraPy SIEM — Trabalho Final

## Como usar este projeto

Este projeto contém a **casca** (esqueleto) do sistema SecuraPy SIEM. Todos os
arquivos `.py` dos módulos já existem com as funções definidas, mas o corpo de
cada função contém apenas `pass` — ou seja, **nada funciona ainda**.

Seu trabalho é **implementar o código** dentro de cada função, seguindo as
docstrings e dicas que já estão escritas nos arquivos.

### Verificando seu progresso com os testes

O projeto inclui **testes automatizados** que validam se sua implementação está
correta. Quando você começar, **todos os testes vão falhar**. Conforme você
implementa as funções, os testes vão passando.

#### Instalando as dependências

```bash
# Na pasta securaPy/
pip install pytest requests
```

#### Rodando todos os testes

```bash
# Na pasta securaPy/
python -m pytest testes/ -v
```

#### Rodando testes de um módulo específico

```bash
# Testar apenas o coletor
python -m pytest testes/test_coletor.py -v

# Testar apenas as regras
python -m pytest testes/test_regras.py -v

# Testar apenas o detector
python -m pytest testes/test_detector.py -v

# Testar apenas o enriquecimento
python -m pytest testes/test_enriquecimento.py -v

# Testar apenas o servidor de alertas
python -m pytest testes/test_servidor.py -v

# Testar apenas os relatórios
python -m pytest testes/test_relatorios.py -v

# Testar apenas a integração (ponta a ponta)
python -m pytest testes/test_integracao.py -v
```

#### Rodando um teste específico

```bash
# Rodar apenas um teste por nome
python -m pytest testes/test_coletor.py::TestParsearLinhaAuth::test_linha_fail_retorna_dict -v
```

#### Vendo quantos testes passam vs falham

```bash
python -m pytest testes/ --tb=no -q
```

Saída esperada no início (tudo falhando):
```
182 failed, 15 passed
```
(os 15 que passam de cara são testes de entrada inválida/vazia — como as funções
ainda não fazem nada, retornar `None` coincide com o comportamento esperado para
entradas inválidas)

Saída esperada quando tudo estiver implementado:
```
197 passed, 0 failed
```

### Ordem recomendada de implementação

Comece pelo módulo que os outros dependem e vá subindo:

1. **`coletor.py`** — base de tudo (rode `test_coletor.py`)
2. **`regras.py`** — precisa do coletor (rode `test_regras.py`)
3. **`detector.py`** — precisa do coletor (rode `test_detector.py`)
4. **`enriquecimento.py`** — independente (rode `test_enriquecimento.py`)
5. **`relatorios.py`** — precisa de todos (rode `test_relatorios.py`)
6. **`servidor_alertas.py` + `cliente_alertas.py`** — independente (rode `test_servidor.py`)
7. **`main.py`** — integra tudo (rode `test_integracao.py`)

### Estrutura do projeto

```
securaPy/
├── main.py                  # Ponto de entrada — menu principal
├── coletor.py               # Módulo 1 — Leitura e parsing de logs
├── regras.py                # Módulo 2 — Motor de regras de detecção
├── detector.py              # Módulo 3 — Detecção de anomalias
├── servidor_alertas.py      # Módulo 4a — Servidor TCP de alertas
├── cliente_alertas.py       # Módulo 4b — Cliente TCP de alertas
├── enriquecimento.py        # Módulo 5 — Consulta API de geolocalização
├── relatorios.py            # Módulo 6 — Dashboard CLI e relatórios
├── logs/                    # Arquivos de log para teste
│   ├── auth.log
│   ├── firewall.log
│   └── web_access.log
├── config/
│   └── regras.json          # Configuração das regras de detecção
├── saida/                   # Relatórios gerados (pasta de saída)
├── testes/                  # Testes automatizados
│   ├── conftest.py          # Fixtures compartilhadas
│   ├── test_coletor.py      # Testes do módulo 1
│   ├── test_regras.py       # Testes do módulo 2
│   ├── test_detector.py     # Testes do módulo 3
│   ├── test_servidor.py     # Testes do módulo 4
│   ├── test_enriquecimento.py  # Testes do módulo 5
│   ├── test_relatorios.py   # Testes do módulo 6
│   └── test_integracao.py   # Testes ponta a ponta
└── README.md                # Este arquivo
```

### Mapa de testes por módulo

| Módulo | Arquivo de teste | Testes | O que valida |
|--------|-----------------|--------|-------------|
| coletor.py | test_coletor.py | 47 | Parsing dos 3 formatos de log, normalização, erros de arquivo |
| regras.py | test_regras.py | 37 | Carregamento JSON, classificação severidade, avaliação de cada regra |
| detector.py | test_detector.py | 38 | Brute force, port scan, blacklist, resumo consolidado |
| enriquecimento.py | test_enriquecimento.py | 26 | IP privado/público, cache, mock de API, tratamento de erros |
| servidor_alertas.py | test_servidor.py | 7 | Formatação de alertas, conexão TCP, broadcast |
| relatorios.py | test_relatorios.py | 30 | Filtros, top IPs, exportação JSON, menu |
| integração | test_integracao.py | 12 | Fluxo completo ponta a ponta |
| | | **197** | **Total** |

---

## Para a entrega: preencha as seções abaixo

> **IMPORTANTE:** Antes de entregar, substitua tudo abaixo deste ponto
> com as informações do seu grupo.

---

# SecuraPy SIEM — [Nome do Grupo]

## Integrantes

| Nome | RM | Responsabilidade |
|------|-----|-----------------|
| [Nome completo] | [RM] | [Módulos que implementou] |
| [Nome completo] | [RM] | [Módulos que implementou] |
| [Nome completo] | [RM] | [Módulos que implementou] |
| [Nome completo] | [RM] | [Módulos que implementou] |

## Descrição

[Descreva em 2-3 parágrafos o que o sistema faz, quais problemas ele resolve
e como os módulos se integram.]

## Como executar

```bash
# 1. Instalar dependências
pip install requests

# 2. Rodar o sistema
cd securaPy
python main.py

# 3. Rodar os testes
python -m pytest testes/ -v
```

## Resultado dos testes

```
[Cole aqui a saída do pytest mostrando quantos testes passam]
```

## Divisão de tarefas

### [Nome — Pessoa A]
- **Módulos:** [lista]
- **O que fez:** [descreva em 2-3 frases]
- **Dificuldades:** [o que foi mais difícil e como resolveu]

### [Nome — Pessoa B]
- **Módulos:** [lista]
- **O que fez:** [descreva em 2-3 frases]
- **Dificuldades:** [o que foi mais difícil e como resolveu]

### [Nome — Pessoa C]
- **Módulos:** [lista]
- **O que fez:** [descreva em 2-3 frases]
- **Dificuldades:** [o que foi mais difícil e como resolveu]

### [Nome — Pessoa D] (se houver)
- **Módulos:** [lista]
- **O que fez:** [descreva em 2-3 frases]
- **Dificuldades:** [o que foi mais difícil e como resolveu]

## Funcionalidades bônus implementadas

- [ ] Correlação temporal (brute force por janela de tempo)
- [ ] Hash de integridade dos logs (hashlib)
- [ ] Geração automática de logs para teste
- [ ] Criação de regras customizadas pelo menu

## Demonstração em vídeo

[Link do vídeo enviado pelo Teams]
