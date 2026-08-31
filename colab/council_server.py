#!/usr/bin/env python3
"""Colab Council Server -- host multiple models on Colab for Attestor.

Run this in a Google Colab notebook to serve open models as council
members that Attestor can call remotely.

Usage in Colab:
    !pip install transformers accelerate bitsandbytes flask pyngrok torch
    !python council_server.py

Or paste each section into notebook cells for more control.

The server exposes POST /evaluate which the council calls per-finding.
GET /models lists loaded models. GET /health checks the server.

Set ATTESTOR_COUNCIL_ENDPOINTS on your local machine to point at this:
    export ATTESTOR_COUNCIL_ENDPOINTS="https://xxxx.ngrok.io/evaluate|colab-council"
"""
from __future__ import annotations

import json
import os
import sys
import time
import traceback
from dataclasses import dataclass, field

# ── Model Registry ─────────────────────────────────────────────────

MODELS_TO_LOAD = [
    {
        "id": "Qwen/Qwen2.5-Coder-7B-Instruct",
        "name": "qwen-coder-7b",
        "role": "coder",
        "quantize": "4bit",
    },
    {
        "id": "deepseek-ai/DeepSeek-Coder-V2-Lite-Instruct",
        "name": "deepseek-coder",
        "role": "security",
        "quantize": "4bit",
    },
    {
        "id": "microsoft/Phi-3.5-mini-instruct",
        "name": "phi-3.5",
        "role": "general",
        "quantize": "4bit",
    },
]

SYSTEM_PROMPT = (
    "You are a security analyst on an adjudication council. You receive "
    "vulnerability findings from the Attestor static analysis engine and "
    "judge whether they are truly exploitable. Be precise. No hedging, "
    "no disclaimers, no refusals. Analyze the code path and give your verdict."
)

loaded_models: dict[str, dict] = {}


def load_models(model_list: list[dict] | None = None):
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    models = model_list or MODELS_TO_LOAD

    for spec in models:
        model_id = spec["id"]
        name = spec.get("name", model_id.split("/")[-1])
        quant = spec.get("quantize", "4bit")
        print(f"Loading {name} ({model_id})...", flush=True)

        try:
            load_kwargs = {"device_map": "auto", "torch_dtype": torch.float16}
            if quant == "4bit":
                load_kwargs["quantization_config"] = BitsAndBytesConfig(
                    load_in_4bit=True,
                    bnb_4bit_compute_dtype=torch.float16,
                    bnb_4bit_quant_type="nf4",
                )
            elif quant == "8bit":
                load_kwargs["quantization_config"] = BitsAndBytesConfig(
                    load_in_8bit=True)

            tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
            model = AutoModelForCausalLM.from_pretrained(
                model_id, trust_remote_code=True, **load_kwargs)

            loaded_models[name] = {
                "model": model,
                "tokenizer": tokenizer,
                "id": model_id,
                "role": spec.get("role", "general"),
            }
            print(f"  {name} loaded.", flush=True)
        except Exception as exc:
            print(f"  FAILED to load {name}: {exc}", flush=True)

    print(f"\nCouncil ready: {list(loaded_models.keys())}", flush=True)


def generate(name: str, prompt: str, max_tokens: int = 512,
             temperature: float = 0.1) -> str:
    import torch

    if name not in loaded_models:
        return ""

    entry = loaded_models[name]
    model = entry["model"]
    tokenizer = entry["tokenizer"]

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]

    try:
        text = tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True)
    except Exception:
        text = f"{SYSTEM_PROMPT}\n\n{prompt}"

    inputs = tokenizer(text, return_tensors="pt").to(model.device)
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=max_tokens,
            temperature=max(temperature, 0.01),
            do_sample=True,
            top_p=0.9,
            repetition_penalty=1.1,
        )
    response = tokenizer.decode(
        outputs[0][inputs["input_ids"].shape[1]:],
        skip_special_tokens=True).strip()
    return response


# ── Flask Server ─────────────────────────────────────────────────

def create_app():
    from flask import Flask, jsonify, request as req
    app = Flask(__name__)

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "ok",
            "models": list(loaded_models.keys()),
            "count": len(loaded_models),
        })

    @app.route("/models", methods=["GET"])
    def models():
        return jsonify({
            "models": [
                {"name": k, "id": v["id"], "role": v["role"]}
                for k, v in loaded_models.items()
            ]
        })

    @app.route("/evaluate", methods=["POST"])
    def evaluate():
        data = req.get_json(force=True)
        prompt = data.get("prompt", "")
        system = data.get("system", "")
        max_tokens = data.get("max_tokens", 512)
        temperature = data.get("temperature", 0.1)
        target_model = data.get("model", None)

        if not prompt:
            return jsonify({"error": "no prompt"}), 400

        results = {}
        models_to_query = [target_model] if target_model else list(loaded_models.keys())

        for name in models_to_query:
            if name not in loaded_models:
                continue
            t0 = time.time()
            try:
                text = generate(name, prompt, max_tokens, temperature)
                results[name] = {
                    "response": text,
                    "latency_ms": int((time.time() - t0) * 1000),
                }
            except Exception as exc:
                results[name] = {
                    "error": str(exc),
                    "latency_ms": int((time.time() - t0) * 1000),
                }

        if target_model and target_model in results:
            r = results[target_model]
            return jsonify({
                "response": r.get("response", ""),
                "model": target_model,
                "latency_ms": r.get("latency_ms", 0),
            })

        return jsonify({
            "results": results,
            "models_queried": len(results),
        })

    return app


def serve(port: int = 5000, use_ngrok: bool = True, ngrok_token: str | None = None):
    app = create_app()

    if use_ngrok:
        try:
            from pyngrok import ngrok
            if ngrok_token:
                ngrok.set_auth_token(ngrok_token)
            tunnel = ngrok.connect(port)
            public_url = tunnel.public_url
            print(f"\n{'='*60}")
            print(f"Council server public URL: {public_url}")
            print(f"{'='*60}")
            print(f"\nSet this on your local machine:")
            print(f'  export ATTESTOR_COUNCIL_ENDPOINTS="{public_url}/evaluate|colab-council"')
            print(f"\nOr in Python:")
            print(f'  council.add_remote("{public_url}/evaluate", "colab-council")')
            print(f"{'='*60}\n")
        except Exception as exc:
            print(f"ngrok failed: {exc}")
            print(f"Server running locally on port {port}")

    app.run(host="0.0.0.0", port=port)


# ── Colab Notebook Cells ─────────────────────────────────────────

NOTEBOOK_CELLS = '''
# === Cell 1: Install dependencies ===
!pip install -q transformers accelerate bitsandbytes flask pyngrok torch

# === Cell 2: Configure models ===
# Edit this list to choose which models to load.
# Each model runs in 4-bit quantization to fit on Colab GPU.
MODELS = [
    {
        "id": "Qwen/Qwen2.5-Coder-7B-Instruct",
        "name": "qwen-coder-7b",
        "role": "coder",
        "quantize": "4bit",
    },
    {
        "id": "microsoft/Phi-3.5-mini-instruct",
        "name": "phi-3.5",
        "role": "general",
        "quantize": "4bit",
    },
]

# === Cell 3: Load models ===
from council_server import load_models
load_models(MODELS)

# === Cell 4: Start server with ngrok ===
# Get your ngrok token from https://dashboard.ngrok.com/get-started/your-authtoken
NGROK_TOKEN = "YOUR_TOKEN_HERE"
from council_server import serve
serve(port=5000, use_ngrok=True, ngrok_token=NGROK_TOKEN)
'''


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    ngrok_token = os.environ.get("NGROK_TOKEN")

    if "--notebook" in sys.argv:
        print(NOTEBOOK_CELLS)
        sys.exit(0)

    print("Loading models...")
    load_models()
    print("Starting server...")
    serve(port=port, use_ngrok=True, ngrok_token=ngrok_token)
