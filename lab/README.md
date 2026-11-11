# Laboratório local: CyberStrikeAI + LM Studio

Este guia sobe o CyberStrikeAI na sua máquina, usando um modelo local servido pelo **LM Studio**, e dois alvos vulneráveis (DVWA e OWASP Juice Shop) em Docker para você testar com segurança.

> Use apenas contra os alvos deste laboratório ou contra sistemas que você tem autorização para testar.

## 1. Pré-requisitos

| Item | Versão |
|------|--------|
| [LM Studio](https://lmstudio.ai) | 0.3.x ou mais novo |
| Go | 1.25+ |
| Python | 3.10+ |
| Docker + Docker Compose | opcional, só para os alvos |
| Ferramentas de segurança (nmap, sqlmap, nuclei, ...) | opcional; Kali já tem quase todas |

## 2. Preparar o LM Studio

1. Baixe um modelo **com suporte a tool calling (function calling)**. O CyberStrikeAI é um agente que depende de chamadas de ferramentas; modelos sem isso só conversam e não executam nada. Bons pontos de partida:
   - `qwen2.5-7b-instruct` / `qwen2.5-14b-instruct` (ou Qwen3)
   - `llama-3.1-8b-instruct`
   - `mistral-nemo-instruct`
   
   Quanto maior o modelo, melhor ele segue os prompts longos do agente. Com 8 GB de VRAM, fique em 7B–8B Q4.
2. Ao carregar o modelo, aumente o **Context Length** para pelo menos **32768**. Os prompts do agente e das ferramentas são grandes; com 4096 tokens o modelo trunca e se perde.
3. Abra a aba **Developer** e clique em **Start Server**. O padrão é `http://127.0.0.1:1234`.
4. Confira:
   ```bash
   curl http://127.0.0.1:1234/v1/models
   ```

> **CyberStrikeAI em outra máquina, VM ou WSL?** Ative **Serve on Local Network** nas configurações do servidor do LM Studio e use o IP da máquina do LM Studio, por exemplo `http://192.168.0.10:1234/v1`. No WSL2 costuma ser o IP do Windows (`ip route | awk '/default/ {print $3}'`).

## 3. Gerar o `config.yaml` apontando para o LM Studio

Na raiz do repositório:

```bash
python3 lab/setup_lmstudio.py
```

O script:
- consulta `GET /v1/models` no LM Studio e escolhe o primeiro modelo de chat carregado (ignora modelos de embedding);
- copia `config.example.yaml` para `config.yaml` trocando o bloco `ai:` por um canal `lmstudio`;
- coloca o servidor web para escutar só em `127.0.0.1`.

Opções úteis:

```bash
# escolher o modelo e o tamanho de contexto (use o mesmo valor configurado no LM Studio)
python3 lab/setup_lmstudio.py --model qwen2.5-14b-instruct --context 32768

# LM Studio em outra máquina
python3 lab/setup_lmstudio.py --base-url http://192.168.0.10:1234/v1

# regravar um config.yaml existente (cria backup config.yaml.bak.<timestamp>)
python3 lab/setup_lmstudio.py --force
```

O bloco gerado fica assim (dá para editar à mão, ou depois em **Configurações do sistema → AI Channel Configuration** na interface web):

```yaml
ai:
  default_channel: lmstudio
  channels:
    lmstudio:
      name: LM Studio (local)
      provider: openai_compatible
      base_url: http://127.0.0.1:1234/v1
      api_key: lm-studio          # qualquer valor; o LM Studio ignora
      model: "qwen2.5-7b-instruct"
      max_total_tokens: 32768     # <= Context Length do LM Studio
      max_completion_tokens: 8192
      reasoning:
        mode: "off"               # não envia campos de reasoning da OpenAI
        allow_client_reasoning: false
```

## 4. Subir o CyberStrikeAI

```bash
chmod +x run.sh
./run.sh --http
```

`--http` evita o aviso de certificado autoassinado; sem ele, o padrão é HTTPS em `https://127.0.0.1:8080`.

Quando aparecer `● ONLINE http://127.0.0.1:8080/`:
1. Copie a senha do `admin` mostrada em **ADMIN SETUP REQUIRED** (ela só aparece uma vez).
2. Acesse `http://127.0.0.1:8080`, entre como `admin` e troque a senha.
3. Em **Configurações do sistema → AI Channel Configuration**, selecione o canal `LM Studio (local)` e use **Probe/Testar** para confirmar que o modelo responde.

> O `run.sh` usa por padrão espelhos chineses (`pypi.tuna.tsinghua.edu.cn`, `goproxy.cn`). Fora da China, é mais rápido usar os oficiais:
> ```bash
> PIP_INDEX_URL=https://pypi.org/simple GOPROXY=https://proxy.golang.org,direct ./run.sh --http
> ```

## 5. Subir os alvos vulneráveis (opcional)

```bash
docker compose -f lab/docker-compose.targets.yml up -d
```

| Alvo | URL | Observação |
|------|-----|------------|
| DVWA | http://127.0.0.1:8880 | login `admin` / `password`, depois clique em **Create / Reset Database** |
| OWASP Juice Shop | http://127.0.0.1:3000 | |

As portas ficam presas em `127.0.0.1`, então os alvos não ficam expostos na sua rede.

Exemplos de pedido no chat do CyberStrikeAI:

- `Faça um scan de portas e serviços em 127.0.0.1 nas portas 3000 e 8880.`
- `Enumere diretórios em http://127.0.0.1:3000 e liste endpoints interessantes.`
- `Teste SQL injection em http://127.0.0.1:8880/vulnerabilities/sqli/?id=1&Submit=Submit usando o cookie "PHPSESSID=<seu cookie>; security=low".`

Para derrubar:

```bash
docker compose -f lab/docker-compose.targets.yml down
```

## 6. Problemas comuns

| Sintoma | Causa provável / solução |
|---------|--------------------------|
| `connection refused` em `:1234` | O servidor do LM Studio não está ligado (Developer → Start Server) ou está em outra máquina sem **Serve on Local Network**. |
| O modelo responde, mas nunca executa ferramentas | O modelo não suporta tool calling, ou é pequeno demais. Troque para Qwen2.5/Qwen3 Instruct ou Llama 3.1 Instruct. |
| Respostas cortadas, erro de contexto excedido, agente "esquece" a tarefa | Aumente o Context Length no LM Studio e ajuste `max_total_tokens` para o mesmo valor (ou `--context` no script). |
| Muito lento | Use quantização menor (Q4_K_M), um modelo menor, ou ative GPU offload no LM Studio. |
| Ferramenta "não encontrada" | Instale o binário correspondente (`sudo apt install nmap sqlmap nikto gobuster ...`); as ausentes são puladas. |
| `client sent an HTTP request to an HTTPS server` | Você subiu sem `--http`; acesse com `https://`. |

Mais detalhes: [docs/en-US/configuration.md](../docs/en-US/configuration.md) e [docs/en-US/troubleshooting.md](../docs/en-US/troubleshooting.md).
