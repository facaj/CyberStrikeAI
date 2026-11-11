#!/usr/bin/env python3
"""Gera config.yaml do CyberStrikeAI apontando para o LM Studio local.

Uso:
  python3 lab/setup_lmstudio.py [--base-url URL] [--model ID] [--context N] [--force]

Sem --model, o script consulta GET <base-url>/models e usa o primeiro modelo de chat.
Só usa a biblioteca padrão do Python.
"""
import argparse
import json
import os
import re
import shutil
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, "config.example.yaml")
TARGET = os.path.join(ROOT, "config.yaml")


def list_models(base_url):
    req = urllib.request.Request(base_url.rstrip("/") + "/models",
                                 headers={"Authorization": "Bearer lm-studio"})
    # LM Studio é local: não passar pelo proxy HTTP do ambiente.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=5) as resp:
        data = json.load(resp)
    return [m.get("id") for m in data.get("data", []) if m.get("id")]


def ai_block(base_url, model, context, completion):
    return f"""ai:
  default_channel: lmstudio
  channels:
    lmstudio:
      name: LM Studio (local)
      provider: openai_compatible
      base_url: {base_url}
      api_key: lm-studio # o LM Studio ignora a chave, mas o campo não pode ficar vazio
      model: {json.dumps(model)}
      max_total_tokens: {context} # deve ser <= Context Length carregado no LM Studio
      max_completion_tokens: {completion}
      reasoning:
        mode: "off" # modelos locais não aceitam campos de reasoning da OpenAI
        allow_client_reasoning: false
"""


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base-url", default=os.environ.get("LMSTUDIO_BASE_URL", "http://127.0.0.1:1234/v1"))
    p.add_argument("--model", default=os.environ.get("LMSTUDIO_MODEL", ""))
    p.add_argument("--context", type=int, default=int(os.environ.get("LMSTUDIO_CONTEXT", "32768")))
    p.add_argument("--force", action="store_true", help="sobrescreve config.yaml existente (faz backup)")
    a = p.parse_args()

    model = a.model
    try:
        models = list_models(a.base_url)
        print(f"[ok] LM Studio respondeu em {a.base_url}: {len(models)} modelo(s)")
        for m in models:
            print(f"     - {m}")
        if not model:
            chat = [m for m in models if "embed" not in m.lower()]
            if not chat:
                sys.exit("[erro] nenhum modelo de chat carregado no LM Studio. Carregue um e rode de novo.")
            model = chat[0]
        elif model not in models:
            print(f"[aviso] modelo '{model}' não está na lista acima; confira o ID no LM Studio.")
    except Exception as e:  # noqa: BLE001
        print(f"[aviso] não consegui falar com o LM Studio em {a.base_url}: {e}")
        print("        Abra o LM Studio > Developer > Start Server (porta 1234).")
        if not model:
            sys.exit("[erro] informe --model <id> ou inicie o servidor do LM Studio.")

    if os.path.exists(TARGET) and not a.force:
        sys.exit(f"[erro] {TARGET} já existe. Use --force para regravar (um backup será criado).")
    if os.path.exists(TARGET):
        bak = f"{TARGET}.bak.{int(time.time())}"
        shutil.copy2(TARGET, bak)
        print(f"[ok] backup em {bak}")

    text = open(EXAMPLE, encoding="utf-8").read()
    completion = min(8192, max(1024, a.context // 4))
    new, n = re.subn(r"(?ms)^ai:\n.*?(?=^\S)", ai_block(a.base_url, model, a.context, completion), text, count=1)
    if n != 1:
        sys.exit("[erro] não encontrei o bloco 'ai:' em config.example.yaml")
    # Laboratório: escuta só em localhost.
    new = re.sub(r"(?m)^(server:\n  host: )0\.0\.0\.0", r"\g<1>127.0.0.1", new, count=1)

    with open(TARGET, "w", encoding="utf-8") as f:
        f.write(new)
    print(f"[ok] {TARGET} gerado com canal 'lmstudio' -> modelo '{model}' (contexto {a.context})")
    print("     Próximo passo: ./run.sh   (ou ./run.sh --http)")


if __name__ == "__main__":
    main()
