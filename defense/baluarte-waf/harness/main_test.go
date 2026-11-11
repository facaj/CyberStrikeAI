// Testa cyberstrikeai.conf com o motor Coraza v3, reproduzindo as requisições
// exatamente como o CyberStrikeAI as monta (ver README.md).
//
//	cd defense/baluarte-waf/harness && go test -v ./...
package harness

import (
	"net/url"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

const setup = `
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html
SecRule REQUEST_HEADERS:Content-Type "^application/x-www-form-urlencoded" "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=URLENCODED"
SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:2,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"
Include ../cyberstrikeai.conf
`

const (
	chromeUA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
	wsUA      = "Mozilla/5.0 (compatible; CyberStrikeAI-WebShell/1.0)"
	beaconUA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	hexToken  = "3f1c0e9a5b7d2e4f6a8c0b1d3e5f7a9c2b4d6e8f0a1c3e5b7d9f1a3c5e7b9d1f"
	formCT    = "application/x-www-form-urlencoded"
	webshellP = "/uploads/img.php"
)

type req struct {
	method, uri, body string
	headers           map[string]string
	respBody          string // se preenchido, roda fase 4
}

func form(kv ...string) string {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v.Encode()
}

func newWAF(t *testing.T) coraza.WAF {
	t.Helper()
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(setup))
	if err != nil {
		t.Fatalf("carregar regras: %v", err)
	}
	return waf
}

// run devolve o ID da regra que interrompeu (0 = passou) e os IDs disparados.
func run(t *testing.T, waf coraza.WAF, r req) (int, []int) {
	t.Helper()
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ProcessConnection("203.0.113.7", 40000, "198.51.100.1", 443)
	tx.ProcessURI(r.uri, r.method, "HTTP/1.1")
	tx.AddRequestHeader("Host", "alvo.example")
	for k, v := range r.headers {
		tx.AddRequestHeader(k, v)
	}
	fired := func() []int {
		var ids []int
		for _, m := range tx.MatchedRules() {
			if id := m.Rule().ID(); id >= 190100 {
				ids = append(ids, id)
			}
		}
		return ids
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return it.RuleID, fired()
	}
	if r.body != "" {
		if it, _, err := tx.WriteRequestBody([]byte(r.body)); err != nil || it != nil {
			if it != nil {
				return it.RuleID, fired()
			}
			t.Fatal(err)
		}
	}
	it, err := tx.ProcessRequestBody()
	if err != nil {
		t.Fatal(err)
	}
	if it != nil {
		return it.RuleID, fired()
	}
	if r.respBody != "" {
		tx.AddResponseHeader("Content-Type", "text/html")
		if it := tx.ProcessResponseHeaders(200, "HTTP/1.1"); it != nil {
			return it.RuleID, fired()
		}
		if it, _, err := tx.WriteResponseBody([]byte(r.respBody)); err != nil || it != nil {
			if it != nil {
				return it.RuleID, fired()
			}
			t.Fatal(err)
		}
		it, err := tx.ProcessResponseBody()
		if err != nil {
			t.Fatal(err)
		}
		if it != nil {
			return it.RuleID, fired()
		}
	}
	return 0, fired()
}

func TestAtaquesBloqueados(t *testing.T) {
	waf := newWAF(t)
	cases := []struct {
		name string
		r    req
		want int
	}{
		{"webshell exec POST com UA padrão", req{method: "POST", uri: webshellP,
			headers: map[string]string{"User-Agent": wsUA, "Content-Type": formCT},
			body:    form("pass", "s3nh4", "cmd", "whoami")}, 190100},
		{"webshell sonda de SO (UA trocado)", req{method: "POST", uri: webshellP,
			headers: map[string]string{"User-Agent": chromeUA, "Content-Type": formCT},
			body:    form("pass", "s3nh4", "cmd", "echo :OSPROBE_%OS%:END")}, 190140},
		{"webshell sonda de SO via GET", req{method: "GET",
			uri:     webshellP + "?" + form("pass", "x", "c", "echo :OSPROBE_%OS%:END"),
			headers: map[string]string{"User-Agent": chromeUA}}, 190140},
		{"webshell listar diretório", req{method: "POST", uri: webshellP,
			headers: map[string]string{"User-Agent": chromeUA, "Content-Type": formCT},
			body:    form("pass", "x", "cmd", "ls -la '/var/www'")}, 190141},
		{"webshell listar diretório Windows", req{method: "POST", uri: webshellP,
			headers: map[string]string{"User-Agent": chromeUA, "Content-Type": formCT},
			body:    form("pass", "x", "z", `dir /a "C:\inetpub"`)}, 190141},
		{"webshell escrita base64", req{method: "POST", uri: "/index.php",
			headers: map[string]string{"User-Agent": chromeUA, "Content-Type": formCT},
			body:    form("k", "x", "cmd", "echo 'PD9waHAgZXZhbCgkX1BPU1RbMV0pOz8+' | base64 -d > '/var/www/a.php'")}, 190142},
		{"beacon C2 check-in (UA truncado)", req{method: "POST", uri: "/check_in",
			headers: map[string]string{"User-Agent": beaconUA, "Content-Type": "application/octet-stream"}}, 190101},
		{"curl_beacon com X-Implant-Token", req{method: "POST", uri: "/check_in",
			headers: map[string]string{"User-Agent": "curl/8.5.0", "X-Implant-Token": "abc", "X-Session-Token": hexToken}}, 190102},
		{"beacon com UA customizado mas X-Session-Token", req{method: "GET", uri: "/tasks?session_id=1",
			headers: map[string]string{"User-Agent": chromeUA, "X-Session-Token": hexToken}}, 190103},
		{"sqlmap", req{method: "GET", uri: "/item?id=1",
			headers: map[string]string{"User-Agent": "sqlmap/1.8.2#stable (https://sqlmap.org)"}}, 190110},
		{"nmap NSE", req{method: "GET", uri: "/",
			headers: map[string]string{"User-Agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"}}, 190110},
		{"ffuf", req{method: "GET", uri: "/FUZZ",
			headers: map[string]string{"User-Agent": "Fuzz Faster U Fool v2.1.0-dev"}}, 190110},
		{"X-Original-URL", req{method: "GET", uri: "/",
			headers: map[string]string{"User-Agent": chromeUA, "X-Original-URL": "/admin"}}, 190120},
		{"XFF loopback", req{method: "POST", uri: "/login",
			headers: map[string]string{"User-Agent": chromeUA, "X-Forwarded-For": "127.0.0.1"}}, 190121},
		{"XFF lista com loopback", req{method: "GET", uri: "/admin",
			headers: map[string]string{"User-Agent": chromeUA, "X-Forwarded-For": "8.8.8.8, 127.0.0.1"}}, 190121},
		{"Spring ..;/", req{method: "GET", uri: "/c/..;/actuator/env",
			headers: map[string]string{"User-Agent": chromeUA}}, 190130},
		{"admin;/", req{method: "GET", uri: "/admin;/",
			headers: map[string]string{"User-Agent": chromeUA}}, 190130},
		{"PATH_INFO jpg/x.php", req{method: "GET", uri: "/uploads/shell.jpg/x.php",
			headers: map[string]string{"User-Agent": chromeUA}}, 190131},
		{"PATH_INFO php/", req{method: "GET", uri: "/denied/file.php/",
			headers: map[string]string{"User-Agent": chromeUA}}, 190131},
		{"codificação dupla", req{method: "GET", uri: "/%2561dmin",
			headers: map[string]string{"User-Agent": chromeUA}}, 190132},
		{"powershell encoded", req{method: "POST", uri: "/api/run",
			headers: map[string]string{"User-Agent": chromeUA, "Content-Type": formCT},
			body:    form("x", "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=")}, 190143},
		{"httpx + XFF privado (score)", req{method: "GET", uri: "/",
			headers: map[string]string{"User-Agent": "python-httpx/0.27.0", "X-Forwarded-For": "10.1.2.3"}}, 190199},
		{"sem UA + X-Real-IP privado (score)", req{method: "GET", uri: "/",
			headers: map[string]string{"X-Real-IP": "192.168.0.10"}}, 190199},
		{"resposta com sonda = webshell ativa", req{method: "GET", uri: "/uploads/old.php",
			headers:  map[string]string{"User-Agent": chromeUA},
			respBody: "<pre>:OSPROBE_Windows_NT:END</pre>"}, 190150},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, fired := run(t, waf, c.r)
			if got != c.want {
				t.Fatalf("interrompido por %d, esperado %d (regras disparadas: %v)", got, c.want, fired)
			}
		})
	}
}

func TestTrafegoLegitimoPassa(t *testing.T) {
	waf := newWAF(t)
	cases := []struct {
		name string
		r    req
	}{
		{"navegador GET /", req{method: "GET", uri: "/", headers: map[string]string{"User-Agent": chromeUA}}},
		{"login com campo pass", req{method: "POST", uri: "/login",
			headers: map[string]string{"User-Agent": chromeUA, "Content-Type": formCT},
			body:    form("user", "maria", "pass", "Senha#Forte1")}},
		{"comentário citando ls -la sem pass", req{method: "POST", uri: "/blog/comentar",
			headers: map[string]string{"User-Agent": chromeUA, "Content-Type": formCT},
			body:    form("texto", "use ls -la para listar")}},
		{"curl de monitoramento (só score 3)", req{method: "GET", uri: "/health",
			headers: map[string]string{"User-Agent": "curl/8.5.0"}}},
		{"app com X-Session-Token comum", req{method: "GET", uri: "/api/perfil",
			headers: map[string]string{"User-Agent": chromeUA, "X-Session-Token": hexToken}}},
		{"rota de hotel /check_in sem tokens", req{method: "POST", uri: "/check_in",
			headers: map[string]string{"User-Agent": chromeUA, "Content-Type": formCT}, body: form("reserva", "123")}},
		{"XFF público legítimo", req{method: "GET", uri: "/",
			headers: map[string]string{"User-Agent": chromeUA, "X-Forwarded-For": "200.160.2.3"}}},
		{"URL com %20", req{method: "GET", uri: "/docs/meu%20arquivo.pdf",
			headers: map[string]string{"User-Agent": chromeUA}}},
		{"query com ponto e vírgula", req{method: "GET", uri: "/busca?q=a;b",
			headers: map[string]string{"User-Agent": chromeUA}}},
		{"resposta normal", req{method: "GET", uri: "/sobre",
			headers: map[string]string{"User-Agent": chromeUA}, respBody: "<h1>Sobre nós</h1>"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, fired := run(t, waf, c.r); got != 0 {
				t.Fatalf("falso positivo: bloqueado por %d (disparadas: %v)", got, fired)
			}
		})
	}
}
