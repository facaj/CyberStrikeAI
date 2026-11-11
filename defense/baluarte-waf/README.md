# Baluarte WAF × CyberStrikeAI

Estudo do CyberStrikeAI do ponto de vista de quem defende, e o que dá para
colocar no Baluarte para detectá-lo e bloqueá-lo.

| Arquivo | Conteúdo |
|---|---|
| `cyberstrikeai.conf` | Regras SecLang (ModSecurity v2/v3 e Coraza v3), IDs 190100–190199 |
| `harness/` | Testes que rodam as regras no Coraza com requisições montadas como o CyberStrikeAI monta |

```bash
cd defense/baluarte-waf/harness && go test -v ./...
```

> O código do Baluarte não estava disponível nesta sessão. As regras foram
> escritas em SecLang porque a maioria dos WAFs carrega esse formato
> (ModSecurity, Coraza, e o OWASP CRS usa o mesmo). Se o Baluarte usa outro
> motor, o mapeamento está na seção 4.

---

## 1. Como a ferramenta funciona

O CyberStrikeAI é um orquestrador de pentest escrito em Go e guiado por LLM.
O agente recebe um objetivo em linguagem natural e decide sozinho quais
ferramentas rodar. Isso é relevante para o WAF por três motivos:

1. **Não há um "scanner CyberStrikeAI".** O tráfego que chega ao alvo vem de
   cerca de 90 ferramentas externas que o agente chama (`tools/*.yaml`: nmap,
   sqlmap, nuclei, ffuf, gobuster, feroxbuster, dirsearch, nikto, wpscan,
   dalfox, xsser, arjun, katana, hydra, wafw00f, ZAP…) e de scripts Python e
   `curl` que o próprio agente escreve na hora (`exec`,
   `execute-python-script`, `http-framework-test` com `httpx`).
2. **Ele foi instruído a contornar WAF.** As skills embarcadas ensinam a
   técnica e mandam continuar quando bloqueado:
   - `skills/redteam-opsec`: rodar um `X-Forwarded-For` aleatório a cada N
     requisições, limitar a taxa (`nuclei -rl`, `nmap -T2`, `ffuf -p`), usar
     jitter aleatório e copiar UA/Referer de navegador;
   - `skills/proxy-tool-bootstrap`: com 403/429, pegar proxies SOCKS5 públicos
     do país do alvo (ProxyScrape), depois proxies HTTP, depois Tor, e trocar
     de IP a cada 20 requisições ou a cada bloqueio;
   - `skills/web-attack-methods`: a ordem de bypass é codificação → protocolo
     → caminho → mutação → IP forjado → smuggling. Também ensina
     `X-Original-URL`/`X-Rewrite-URL`, `/admin;/`, `..;/` do Spring,
     `%2561dmin`, PATH_INFO (`shell.jpg/x.php`), upgrade para WebSocket para
     fugir de filtro por URL e procura do IP de origem por trás da CDN;
   - `skills/specialized-attack-playbooks`: identificar o WAF/CDN pelo
     **tamanho da página de bloqueio** (por exemplo "~2000 bytes = WAF da CDN,
     146 bytes = 404 do nginx");
   - `skills/unlimited-attack-scope`: "被拦换路，不达不休", ou seja, se for
     bloqueado, troque de caminho e não pare até conseguir.
3. **Ele tem cliente de WebShell e C2 próprios**, com assinaturas fixas no
   código. São as detecções de maior confiança (seção 2.1).

O "Tool call guard" da ferramenta bloqueia por padrão só domínios `.gov`
(`internal/toolguard/toolguard.go`), e o operador pode desligar isso. Não
conte com ele como proteção.

## 2. Assinaturas encontradas no código

### 2.1 Alta confiança (podem bloquear direto)

| Assinatura | Origem | Regra |
|---|---|---|
| `User-Agent: Mozilla/5.0 (compatible; CyberStrikeAI-WebShell/1.0)` | `internal/handler/webshell.go`, `webshell_probe.go` | 190100 |
| Sonda de SO `echo :OSPROBE_%OS%:END`, enviada antes da primeira operação de arquivo quando o SO está em "auto" | `internal/handler/webshell_probe.go` | 190140 |
| Resposta `:OSPROBE_Windows_NT:END` / `:OSPROBE_%OS%:END`, que indica **WebShell já ativa** no servidor | idem | 190150 |
| Protocolo WebShell `pass=<senha>&<cmd>=<comando>` (GET ou POST form) com `ls -la`, `dir /a`, `cat`, `type`, `rm -f`, `mkdir -p`, `mv -f`… | `execParams`/`buildFileCommand` em `webshell.go` | 190141 |
| Upload/escrita `echo '<b64>' \| base64 -d > arquivo` ou PowerShell `FromBase64String`+`WriteAllBytes` | `webshell.go` | 190142 |
| Beacon C2 com UA truncado `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36`, sem `(KHTML, like Gecko) Chrome/…`. Nenhum navegador envia isso | `internal/c2/payload_builder.go` | 190101 |
| Cabeçalhos `X-Implant-Token` e `X-Session-Token` (64 hex) nas rotas padrão `/check_in`, `/tasks`, `/result`, `/upload`, `/file/` | `beacon.go.tmpl`, `payload_oneliner.go`, `internal/c2/types.go` | 190102, 190103 |
| One-liners: `powershell … -EncodedCommand`, `Net.Sockets.TcpClient(`, `bash -i >& /dev/tcp/…` | `internal/c2/payload_oneliner.go` | 190143 |

O tráfego de C2 vai **do servidor comprometido para o atacante**. Se o
Baluarte só filtra a entrada, as regras 190101–190103 pegam o caso em que o
atacante tenta falar com um beacon através do site. O ideal é aplicar a mesma
lógica no **proxy de saída**.

### 2.2 Média confiança (UA padrão das ferramentas, que pode ser trocado)

Regra 190110: sqlmap, Nikto, Nmap Scripting Engine, Nuclei, ffuf ("Fuzz
Faster U Fool"), gobuster, feroxbuster, WPScan, masscan, zgrab, Hydra,
wfuzz, jaeles, xsser, dalfox, ZAP. O OWASP CRS já tem algo parecido (913100),
e esta regra cobre o caso sem CRS.

### 2.3 Sinais fracos (somam pontos)

Regras 190111, 190112, 190122, que juntas bloqueiam com score ≥ 5 (190199):
UA de biblioteca (`python-httpx`, `python-requests`, `Go-http-client`,
`curl/`), ausência de UA e IP privado em cabeçalho de proxy. Um `curl` de
monitoramento sozinho soma 3 e passa.

### 2.4 Técnicas de bypass ensinadas pelas skills

| Técnica | Regra |
|---|---|
| `X-Original-URL` / `X-Rewrite-URL` vindos do cliente | 190120 |
| `X-Forwarded-For`/`X-Real-IP`/`True-Client-IP`/… com loopback | 190121 |
| `..;/`, `/admin;/` (path parameter Spring/Tomcat) | 190130 |
| PATH_INFO: `file.php/`, `shell.jpg/x.php` | 190131 |
| Codificação dupla `%25xx` | 190132 |

## 3. O que regra não resolve: mudanças no motor do Baluarte

O agente troca de UA, IP e ritmo quando é bloqueado, então a defesa que dura
é a **comportamental**. Estes são os pontos a implementar no código do
Baluarte, em ordem de impacto:

1. **Não confiar em cabeçalhos de IP do cliente.** Descobrir o IP real só a
   partir de proxies confiáveis configurados (lista de CIDRs da CDN/LB). Fora
   disso, descartar `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`,
   `CF-Connecting-IP` e `Forwarded` antes de qualquer decisão e antes de
   repassar ao backend. Isso derruba o bypass nº 1 da skill de OPSEC, que é
   também o que a 190121 cobre só em parte.
2. **Limitar taxa por impressão digital, não só por IP.** Como o agente roda
   proxies, a chave do rate limit e do banimento deve incluir o fingerprint
   TLS (JA4/JA3) e o fingerprint HTTP (ordem e conjunto de cabeçalhos, HTTP/1.1
   vs h2). `Go net/http` (beacon, cliente WebShell), `python-httpx` e `curl`
   têm JA4 bem diferentes do Chrome **mesmo com o UA trocado**. Um UA de
   Chrome com JA4 de Go ou Python já é motivo para bloquear.
3. **Bloquear saídas de Tor e proxies públicos.** Importar periodicamente a
   lista de exit nodes do Tor e listas de proxies abertos (as mesmas fontes que
   a skill usa, como ProxyScrape). Em geral é o terceiro recurso do agente
   depois de um bloqueio.
4. **Banimento progressivo por comportamento de varredura**: proporção de
   404/403 por fingerprint, muitas URLs distintas em pouco tempo, mesmo
   fingerprint vindo de vários IPs, e acesso a **caminhos-isca** (`/.env`,
   `/actuator/env`, `/.git/config`, `/admin..;/`, `/phpinfo.php`) que nenhum
   usuário legítimo acessa. Um acesso a isca bane o fingerprint, não só o IP.
5. **Página de bloqueio uniforme.** A skill identifica o WAF pelo tamanho da
   resposta. Usar o mesmo corpo e status (ou o 404 padrão da aplicação) para
   bloqueio, rota inexistente e rota negada tira essa informação do agente.
   Variar levemente o tamanho também atrapalha o diff de respostas.
6. **WebSocket e protocolos alternativos.** Aplicar as mesmas regras no
   handshake `Upgrade: websocket` e inspecionar frames, ou limitar quais
   caminhos aceitam upgrade. A skill usa WS justamente para fugir de filtro por
   URL.
7. **Fechar a origem.** O backend deve aceitar conexões só do Baluarte
   (firewall/mTLS/allowlist). A skill procura o IP de origem por DNS
   histórico, CT logs e Shodan para pular a CDN/WAF.
8. **Normalizar antes de inspecionar.** Decodificar até um ponto fixo,
   resolver `..;`, `;param`, barras duplas e Unicode, e rejeitar
   ambiguidades (`Content-Length` + `Transfer-Encoding`, CL duplicado), porque
   "走私" (smuggling) é o último passo da árvore de bypass.
9. **Resposta (DLP).** Inspecionar respostas para a sonda `OSPROBE` (190150) e
   saídas típicas de comando (`uid=…(…) gid=`, `Volume Serial Number`,
   `drwxr-xr-x`). Se aparecerem, há um incidente, não só uma tentativa.

**Sobre "injetar prompt" na página de bloqueio** (por exemplo, um texto
dizendo à IA que o alvo não está autorizado): custa pouco e alguns modelos
param, mas a ferramenta foi instruída explicitamente a continuar ("不达不休").
Use isso como complemento, nunca como controle.

## 4. Integração

- **ModSecurity (nginx/Apache) ou Coraza** (por exemplo
  `coraza-caddy`, `coraza-proxy-wasm`, ou Go com `github.com/corazawaf/coraza/v3`):
  depois do setup do CRS (ou do equivalente ao `setup` em
  `harness/main_test.go`):
  ```
  Include /caminho/defense/baluarte-waf/cyberstrikeai.conf
  ```
  A regra 190150 precisa de `SecResponseBodyAccess On`.
- **Motor próprio**: cada regra é um par (campo, regex) com a ação
  descrita no comentário. Os testes em `harness/` servem de casos de
  aceitação para portar a lógica.
- **Atrás de CDN/LB**: revise 190121/190122 junto com o item 3.1, porque a
  CDN preenche `X-Forwarded-For` de forma legítima (mas nunca com loopback).
- Para começar com segurança, rode uma semana com `SecRuleEngine
  DetectionOnly` e acompanhe as tags `cyberstrikeai/*` no log.

## 5. Testes

`harness/main_test.go` monta as requisições com os mesmos parâmetros que o
código do CyberStrikeAI usa e roda as regras no Coraza v3:

- **24 ataques** bloqueados pela regra esperada: WebShell com UA padrão e com
  UA trocado (GET/POST, Linux/Windows), escrita base64, beacon, curl_beacon,
  scanners, XFF loopback, `..;/`, `;/`, PATH_INFO, `%2561`, PowerShell
  codificado, score combinado e a resposta de WebShell ativa;
- **10 tráfegos legítimos** que passam: navegador comum, login com campo
  `pass`, comentário com "ls -la", `curl` de health check, app que usa
  `X-Session-Token`, rota `/check_in` de negócio, XFF público, `%20`, `;` na
  query, resposta normal.

Limitação: os UAs padrão de terceiros (2.2) e os sinais fracos são triviais de
trocar. Contra um operador cuidadoso, quem segura são a seção 2.1 (enquanto
ele usar os clientes embutidos) e a seção 3.
