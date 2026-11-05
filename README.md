# hackbot

Harness de pentest orquestrado por um agente LLM (ReAct + LangGraph).
O LLM decide dinamicamente quais ferramentas chamar; o scope guard e o budget
protegem o alvo e o custo.

## Setup

    pip install -e ".[dev]"
    cp .env.example .env   # configure OPENAI_API_KEY (ou DeepSeek/GLM/Anthropic)
    # edite scope.json com o alvo autorizado

## Uso

    hackbot check-scope http://localhost:3000 scope.json
    hackbot run --target http://localhost:3000 --scope-file scope.json --dry-run
    hackbot run --target http://juice-shop.lab --scope-file scope.json --no-dry-run
    hackbot demo --dry-run   # smoke test com LLM fake, sem custo

## Trocar de modelo (ex: DeepSeek, GLM/Zhipu, Anthropic)

    export PH_LLM_PROVIDER=openai
    export PH_LLM_MODEL=deepseek-chat
    export PH_LLM_BASE_URL=https://api.deepseek.com/v1
    export PH_OPENAI_API_KEY=sk-...

    export PH_LLM_PROVIDER=anthropic
    export PH_LLM_MODEL=claude-3-5-sonnet-latest
    export PH_ANTHROPIC_API_KEY=sk-ant-...

## Ferramentas expostas ao agente

- `http_probe(url, method, headers, body)` — requisição HTTP (scope-guarded, rate-limited)
- `scan_js_bundle(url)` — baixa JS e procura segredos/cartões/exfil
- `analyze_text_for_secrets(text)` — regex de segredos (sk-, AKIA, JWT, card)
- `save_finding(title, severity, evidence, url)` — registra achado
- `check_scope(url)` — valida URL no escopo
- `finish(reason)` — encerra o loop e dispara o relatório
