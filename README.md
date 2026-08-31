# Web Vuln Scanner

Scanner de vulnerabilidades web não destrutivo: rastreia um alvo autorizado, descobre a
superfície de requisição (links, parâmetros GET e formulários) e roda um conjunto de
verificações sobre ela, com relatório no terminal e em HTML, e uma interface no terminal
para acompanhar o scan enquanto ele acontece.

Nada sai do escopo definido no início — toda requisição passa por um único cliente HTTP
que valida o alvo, aplica ritmo e desconta de um orçamento global. Não há exploração
destrutiva, extração de dados, força bruta nem tentativa de bypass de autenticação.

Python 3.12 · requests · BeautifulSoup · Rich · Textual

## Finalidade

Automatizar o reconhecimento inicial de uma aplicação em teste autorizado: mapear onde
ela recebe entrada, apontar o que merece análise manual e explicar cada achado com
evidência, severidade, confiança e correção — sem gerar carga acidental no alvo e sem
declarar vulnerabilidade a partir de sinal fraco.

É uma plataforma pequena, não um script: adicionar uma verificação é escrever uma classe
e registrá-la, sem tocar no motor.

## Como funciona

```text
alvo ──> crawler ──> mapa do site ──> scanners ──> achados ──> console + HTML
             └─────────────── tudo passa pelo cliente HTTP ──────────────┘
                       escopo · ritmo · timeout · orçamento
```

- **Escopo imutável** — construído uma vez a partir do alvo; nada descoberto durante a
  execução amplia os hosts permitidos. Redirects são seguidos manualmente, salto a salto
- **Cliente HTTP único** — nenhum outro módulo chama `requests`: ritmo, timeout, limite
  de resposta e orçamento global são aplicados por construção
- **Crawler** — busca em largura com normalização de URL, deduplicação e limites de
  profundidade e páginas. Só descobre superfície; não testa nada
- **Scanners como plugin** — cada verificação implementa a mesma interface e se registra
  por nome; falha de uma é isolada e não derruba as demais
- **Severidade e confiança separadas** — "quão grave se for real" e "quão certo estou"
  são perguntas diferentes, e cada achado justifica as duas
- **Segredos redigidos** — cookies e cabeçalhos de autorização do operador nunca chegam
  ao log nem ao relatório

| Scanner | Detecta | Severidade máx. |
|---|---|---|
| `xss` | XSS refletido | ALTA |
| `sqli` | SQL injection | ALTA |
| `headers` | Cabeçalhos de segurança e flags de cookie | MÉDIA |
| `auth-surface` | Superfície de autenticação | INFO |

Nenhuma acusa por sinal fraco:

- **`xss`** — só reporta se os caracteres de escape voltarem **sem codificação**;
  codificada vira INFO. O contexto (texto, atributo, `<script>`) define a severidade
- **`sqli`** — error-based exige o erro de banco na sondagem e **não** no controle;
  boolean-based exige que a verdadeira pareça a baseline **e** divirja da falsa
- **`headers`** — presença de cabeçalho é fato, não inferência: HSTS só é cobrado sob
  HTTPS, e CSP ausente é média, não alta
- **`auth-surface`** — inventário apenas: aponta onde há login para revisão manual, sem
  tentar autenticar, burlar ou adivinhar credencial

## Como rodar

Requer Python 3.12+:

```sh
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

.venv/bin/python -m scanner --target http://127.0.0.1:8000 --output relatorio.html
```

Selecionando verificações e ajustando o ritmo:

```sh
.venv/bin/python -m scanner --target http://127.0.0.1:8000 \
    --scanner xss --scanner headers --max-pages 100 --requests-per-second 2
```

| Opção | Padrão | Função |
|---|---|---|
| `--target` | — | URL raiz a analisar (obrigatório) |
| `--max-depth` / `--max-pages` | `3` / `50` | Profundidade e páginas |
| `--max-requests` | `500` | Teto rígido da execução inteira |
| `--delay` / `--requests-per-second` | `0.5` / — | Ritmo; vence o mais restritivo |
| `--timeout` / `--max-redirects` | `10` / `5` | Timeout e redirects seguidos |
| `--max-response-bytes` | `2 MiB` | Corpo máximo lido por resposta |
| `--scope-host` / `--allow-subdomains` / `--path-prefix` | — | Ajusta o escopo |
| `--header` / `--cookie` / `--user-agent` | — | Molda a requisição (repetíveis) |
| `--scanner` | todos | Seleciona verificações por nome (repetível) |
| `--output` | — | Grava relatório HTML autocontido |
| `--insecure` | desligado | Desliga TLS (homologação; fica no log) |
| `--verbose` / `--quiet` / `--no-color` | — | Verbosidade e cor do console |

Sai com código 1 quando há achado acima de INFO, o que permite usar como gate de CI.

## Interface no terminal

A CLI devolve tudo no fim; a interface mostra o scan enquanto ele acontece. Um
arquivo executável prepara o ambiente e abre a interface:

```sh
./launch-tui --target http://127.0.0.1:8000
```

Ele cria `.venv` no próprio repositório, instala o pacote com o extra `tui` e
entrega o controle. Não usa `sudo`, não instala pacote de sistema e não escreve
fora do repositório. Quem já tem o ambiente pronto pode chamar direto:

```sh
.venv/bin/pip install -e ".[tui]"
.venv/bin/web-vuln-scanner-tui --target http://127.0.0.1:8000
```

O formato é o de um proxy de interceptação: uma árvore do alvo, o histórico de
requisições com o par requisição/resposta embaixo, e a lista de achados com a
evidência de cada um.

| Aba | Mostra |
|---|---|
| Dashboard | Distribuição por severidade, números do run, erros não fatais |
| Target | Árvore das URLs que o scan tocou |
| HTTP history | Cada requisição enviada, com requisição e resposta completas |
| Findings | Achados ordenados por severidade, com filtro e evidência |
| Log | O stream de log do motor, ao vivo |

| Tecla | Ação |
|---|---|
| `ctrl+r` | Inicia o scan |
| `ctrl+x` | Para no próximo limite de requisição |
| `ctrl+e` | Grava o relatório HTML |
| `f` | Cicla o filtro de severidade |
| `ctrl+q` | Sai |

Três decisões que mudam o que a interface afirma:

- **A interface não amplia nada.** Ela monta o mesmo `ScanConfig` que a CLI monta
  e chama o mesmo motor. Escopo, ritmo e orçamento continuam sendo aplicados no
  cliente HTTP, que segue sendo o ponto único de saída
- **Segredos são redigidos na origem.** O registro de cada troca já nasce
  redigido, não na hora de exibir. Um painel de histórico é exatamente onde um
  cookie de sessão vazaria num compartilhamento de tela, e redigir na construção
  significa que nenhum consumidor consegue renderizar um segredo por engano
- **Run cancelado não vira relatório.** Parar no meio é legítimo e o que já foi
  encontrado continua na tela, marcado como parcial — mas o `ctrl+e` fica
  desabilitado, porque um alvo meio rastreado apresentado como relatório afirma
  "procuramos e achamos isto", que é a única coisa que um scan interrompido não
  pode dizer

O histórico é limitado: 2000 trocas registradas e 256 KiB de corpo por troca. O
que passa disso aparece na barra de status como `not recorded`, porque uma
requisição não registrada ainda foi enviada, e um histórico curto não pode ser
lido como um scan curto.

## Testes

O repositório traz uma aplicação deliberadamente vulnerável em `http.server` (stdlib),
que sobe em `127.0.0.1` numa porta aleatória. Os testes de integração rodam um scan
completo contra ela — nenhum serviço externo é contatado.

```sh
.venv/bin/pytest                    # 155 testes: unitários + integração
.venv/bin/pytest --cov=scanner      # com cobertura
.venv/bin/ruff check . && .venv/bin/ruff format --check .
```

Para experimentar na mão, suba a aplicação vulnerável e aponte o scanner para ela:

```sh
.venv/bin/python -m tests.fixtures.vulnerable_app     # http://127.0.0.1:8000
```

A interface é testada pelo piloto headless do Textual contra a mesma aplicação,
e não por chamadas diretas aos seus métodos: os defeitos que ela realmente teve
não eram erros de lógica. Um timer que sobreviveu aos widgets, uma thread de
scan que sobreviveu à janela, e um layout que jogava botões e checkboxes para
além da borda direita — presentes no DOM, encontráveis por uma query, e
invisíveis para o operador. Por isso existe um teste que confere a **geometria**
de cada controle em quatro larguras de terminal, de 80 colunas para cima.

A CI roda a suíte em Python 3.12 e 3.13 mais `ruff` a cada push e pull request.

## Limitações

- **Não executa JavaScript** — XSS aponta reflexão sem codificação, que é execução
  *potencial*; confirmar exige navegador, e a ferramenta nunca afirma ter confirmado
- **SQL injection é heurística** — boolean-based compara similaridade de resposta, e
  página muito dinâmica pode imitar o sinal (daí a confiança média, não alta)
- **Só rastreia HTML estático** — sem SPA, sem links via JS, sem fluxo autenticado
- **Ausência de achado não prova ausência de vulnerabilidade** — o alvo é um punhado de
  classes comuns e de sinal forte, não cobertura ampla

## Uso autorizado

Ferramenta para teste de segurança autorizado e estudo. Use apenas contra sistemas que
você mantém ou para os quais tem permissão explícita e por escrito; varredura não
autorizada pode ser ilegal.

Por construção não há aqui exploração destrutiva, alteração ou exclusão de dados,
extração de banco, execução remota de comando, força bruta, credential stuffing, bypass
de autenticação, persistência nem negação de serviço.

## Licença

MIT — ver `LICENSE`.
