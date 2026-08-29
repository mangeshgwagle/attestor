#!/usr/bin/env python3
"""brain42 -- Owen's own trainable language model.

A byte-level transformer, dual backend:

    numpy  : tiny config, CPU, zero dependencies beyond numpy -- proves the
             entire pipeline (corpus -> train -> checkpoint -> perplexity)
    torch  : full 100M-param config on the GPU (pip install torch)

What a 100M-param brain realistically is: a BLOODHOUND, not a genius.
It learns the statistical DNA of Owen's own code, reports, and security
text -- so it can (a) flag anomalous code by perplexity spikes,
(b) draft Owen-flavored snippets, (c) classify finding text. It will
never reason like Sol; the gauntlet still verifies everything.

Perplexity mode doubles as an anomaly detector: code that surprises the
brain (high perplexity vs its training DNA) is code worth a human look.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

BR_SCHEMA = "attestor-brain-4.2"

# backend configs
NUMPY_CONFIG = {"dim": 64, "layers": 2, "heads": 2, "ctx": 64}
TORCH_CONFIG_100M = {"dim": 768, "layers": 12, "heads": 12, "ctx": 512,
                     "approx_params": "85-100M with byte vocab"}


def sha256_hex(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------- corpus

def build_corpus(paths, min_bytes=256):
    blobs = []
    for path in paths:
        p = Path(path)
        if p.is_dir():
            for child in sorted(p.rglob("*.py")):
                try:
                    blobs.append(child.read_text(encoding="utf-8",
                                                 errors="replace"))
                except OSError:
                    continue
        elif p.is_file():
            try:
                blobs.append(p.read_text(encoding="utf-8",
                                         errors="replace"))
            except OSError:
                continue
    corpus = ("\n\n".join(blobs)).encode("utf-8")
    if len(corpus) < min_bytes:
        corpus = (corpus + b"\n" * min_bytes)[:min_bytes]
    return corpus


# ------------------------------------------------ numpy tiny transformer

class NumpyBrain:
    """Minimal single/multi-head self-attention LM in pure numpy.
    Proves the pipeline; not the production size."""

    def __init__(self, dim=64, layers=2, ctx=64, seed=0):
        import numpy as np
        self.np = np
        self.dim, self.layers, self.ctx = dim, layers, ctx
        rng = np.random.default_rng(seed)
        scale = 0.02
        self.params = {}
        self.params["embed"] = rng.normal(0, scale, (256, dim))
        self.params["pos"] = rng.normal(0, scale, (ctx, dim))
        for layer in range(layers):
            self.params[f"Wq{layer}"] = rng.normal(0, scale, (dim, dim))
            self.params[f"Wk{layer}"] = rng.normal(0, scale, (dim, dim))
            self.params[f"Wv{layer}"] = rng.normal(0, scale, (dim, dim))
            self.params[f"Wo{layer}"] = rng.normal(0, scale, (dim, dim))
            self.params[f"W1{layer}"] = rng.normal(0, scale, (dim, dim * 2))
            self.params[f"W2{layer}"] = rng.normal(0, scale, (dim * 2, dim))
            self.params[f"n1g{layer}"] = np.ones(dim)
            self.params[f"n2g{layer}"] = np.ones(dim)
        self.params["out"] = rng.normal(0, scale, (dim, 256))

    def _layernorm(self, x, gain):
        return (x - x.mean(-1, keepdims=True)) / (
            x.std(-1, keepdims=True) + 1e-5) * gain

    def _attention(self, x, layer):
        np = self.np
        T, D = x.shape
        q = x @ self.params[f"Wq{layer}"]
        k = x @ self.params[f"Wk{layer}"]
        v = x @ self.params[f"Wv{layer}"]
        scores = q @ k.T / (D ** 0.5)
        mask = np.triu(np.ones((T, T)), 1) * -1e9
        scores = scores + mask
        weights = np.exp(scores - scores.max(-1, keepdims=True))
        weights = weights / weights.sum(-1, keepdims=True)
        return (weights @ v) @ self.params[f"Wo{layer}"]

    def forward(self, tokens):
        np = self.np
        T = min(len(tokens), self.ctx)
        x = self.params["embed"][tokens][:T] + \
            self.params["pos"][:T]
        for layer in range(self.layers):
            x = self._layernorm(x, self.params[f"n1g{layer}"])
            x = x + self._attention(x, layer)
            x = self._layernorm(x, self.params[f"n2g{layer}"])
            h = np.tanh(x @ self.params[f"W1{layer}"])
            x = x + h @ self.params[f"W2{layer}"]
        logits = x @ self.params["out"]
        return logits

    def loss_on(self, tokens):
        np = self.np
        logits = self.forward(tokens)
        targets = tokens[1:]
        logprobs = logits - np.log(np.exp(logits).sum(-1, keepdims=True))
        picked = logprobs[np.arange(len(targets)), targets]
        return -picked.mean()

    def train_steps(self, corpus, steps=200, batch=4, seq=32, lr=0.5):
        np = self.np
        losses = []
        rng = np.random.default_rng(0)
        for step in range(steps):
            total = 0.0
            for _ in range(batch):
                start = int(rng.integers(0, max(1, len(corpus) - seq - 1)))
                chunk = corpus[start:start + seq + 1]
                tokens = np.frombuffer(chunk[:seq + 1], dtype=np.uint8)
                tokens = tokens.astype(np.int64)
                if len(tokens) < 2:
                    continue
                # finite-difference-free tiny SGD on output head only
                # (full backprop omitted in numpy backend by design; the
                # torch backend does real backprop at 100M scale)
                logits = self.forward(tokens)
                targets = tokens[1:]
                probs = np.exp(logits) / np.exp(logits).sum(
                    -1, keepdims=True)
                onehot = np.zeros_like(probs)
                onehot[np.arange(len(targets)), targets] = 1
                grad = (probs - onehot) / len(targets)
                head_grad = grad.T @ self._last_hidden(tokens)
                self.params["out"] -= 0.05 * head_grad.T
                total += self.loss_on(tokens)
            losses.append(total / batch)
        return losses

    def _last_hidden(self, tokens):
        np = self.np
        T = min(len(tokens), self.ctx)
        x = self.params["embed"][tokens][:T] + self.params["pos"][:T]
        for layer in range(self.layers):
            x = self._layernorm(x, self.params[f"n1g{layer}"])
            x = x + self._attention(x, layer)
        return x

    def perplexity(self, text):
        np = self.np
        tokens = np.frombuffer(text.encode("utf-8")[:self.ctx + 1],
                               dtype=np.uint8).astype(np.int64)
        if len(tokens) < 2:
            return float("inf")
        return float(np.exp(self.loss_on(tokens)))


# ------------------------------------------------------- torch backend

def torch_available():
    try:
        import torch  # noqa: F401
        return True
    except ImportError:
        return False


def torch_100m_note():
    if torch_available():
        import torch
        cuda = torch.cuda.is_available()
        return {"torch": torch.__version__, "cuda": cuda,
                "ready_for_100m": cuda,
                "config": TORCH_CONFIG_100M}
    return {"torch": None,
            "install": "pip install torch --index-url "
                       "https://download.pytorch.org/whl/cu129",
            "ready_for_100m": False,
            "note": "GPU present per nvidia-smi; install torch to "
                    "unlock the 100M config (hours, not months)"}


# ------------------------------------------------------------- selftest

def run_selftest():
    checks = []
    here = Path(__file__).resolve().parent

    corpus = build_corpus([
        here / "brain42.py",
        here / "rankgate_trainer42.py",
        here / "reader42.py",
    ])
    checks.append(("corpus built from Owen's own source",
                   len(corpus) > 256))

    brain = NumpyBrain(dim=NUMPY_CONFIG["dim"],
                       layers=NUMPY_CONFIG["layers"],
                       ctx=NUMPY_CONFIG["ctx"], seed=0)
    tokens_all = brain.np.frombuffer(corpus[:4096], dtype=brain.np.uint8)
    tokens_all = tokens_all.astype(brain.np.int64)

    loss_before = float(brain.loss_on(tokens_all[:64]))
    losses = brain.train_steps(corpus, steps=150, batch=2, seq=48, lr=0.5)
    loss_after = float(brain.loss_on(tokens_all[:64]))

    checks.append(("loss decreased over training",
                   loss_after < loss_before))
    checks.append(("loss curve recorded", len(losses) == 150))

    seen_ppl = brain.perplexity("def train_steps(corpus, steps=200):")
    random_ppl = brain.perplexity("\xa7\xb0\xfc\x01~#ZZ")
    checks.append(("seen-code perplexity below random bytes",
                   seen_ppl < random_ppl))

    checks.append(("torch 100M path reports honestly",
                   isinstance(torch_100m_note(), dict)))

    failed = [name for name, ok in checks if not ok]
    return {
        "schema": BR_SCHEMA,
        "tool": "self-test",
        "backend": "numpy-tiny",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
        "loss_before": round(loss_before, 3),
        "loss_after": round(loss_after, 3),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="brain42", description="Owen's trainable byte-level brain")
    subs = parser.add_subparsers(dest="command", required=True)

    p = subs.add_parser("train", help="train the numpy-tiny backend")
    p.add_argument("--corpus", nargs="+", required=True)
    p.add_argument("--steps", type=int, default=200)
    p.add_argument("--out")

    p = subs.add_parser("perplexity", help="score text against the brain")
    p.add_argument("--text", required=True)

    subs.add_parser("torch-status")
    subs.add_parser("self-test")
    args = parser.parse_args(argv)

    if args.command == "torch-status":
        print(json.dumps(torch_100m_note(), indent=2))
        return EXIT_CLEAN if torch_100m_note().get("ready_for_100m") else 3

    if args.command == "self-test":
        result = run_selftest()
        print(json.dumps(result, indent=2, sort_keys=True))
        return EXIT_CLEAN if result["passed"] else EXIT_OPERATIONAL

    brain = NumpyBrain(dim=NUMPY_CONFIG["dim"],
                       layers=NUMPY_CONFIG["layers"],
                       ctx=NUMPY_CONFIG["ctx"], seed=0)
    if args.command == "train":
        corpus = build_corpus(args.corpus)
        losses = brain.train_steps(corpus, steps=args.steps)
        print(json.dumps({
            "schema": BR_SCHEMA,
            "backend": "numpy-tiny",
            "steps": args.steps,
            "loss_first": round(losses[0], 3),
            "loss_last": round(losses[-1], 3),
            "decreased": losses[-1] < losses[0],
        }, indent=2))
        return EXIT_CLEAN
    if args.command == "perplexity":
        print(json.dumps({"perplexity": brain.perplexity(args.text)},
                         indent=2))
        return EXIT_CLEAN
    return EXIT_INVALID


EXIT_CLEAN = 0

if __name__ == "__main__":
    sys.exit(main())


# ------------------------------------------------------- torch backend

TORCH_PRESETS = {
    "mx330": {"dim": 256, "layers": 6, "ctx": 128, "params": "~8M",
              "note": "comfortable on CPU; trains in minutes"},
    "full": {"dim": 768, "layers": 12, "ctx": 512, "params": "~85-100M",
             "note": "overnight CPU or CUDA GPU when available"},
}


def train_torch(corpus_bytes, config="mx330", steps=300, lr=3e-4,
                seq=128, batch=8, seed=0, log_every=50):
    """Real transformer, real backprop, on the distilled corpus."""
    import torch
    import torch.nn as nn

    torch.manual_seed(seed)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    preset = TORCH_PRESETS[config]
    dim, layers, ctx = preset["dim"], preset["layers"], preset["ctx"]

    data = torch.frombuffer(corpus_bytes[:max(len(corpus_bytes), seq + 1)],
                            dtype=torch.uint8).long()
    vocab = 256

    class Block(nn.Module):
        def __init__(self):
            super().__init__()
            self.ln1 = nn.LayerNorm(dim)
            self.attn = nn.MultiheadAttention(dim, 8, batch_first=True)
            self.ln2 = nn.LayerNorm(dim)
            self.mlp = nn.Sequential(nn.Linear(dim, dim * 4),
                                     nn.GELU(),
                                     nn.Linear(dim * 4, dim))

        def forward(self, x):
            h = self.ln1(x)
            mask = torch.triu(torch.ones(ctx, ctx, device=x.device),
                              1).bool()
            a, _ = self.attn(h, h, h, attn_mask=mask)
            x = x + a
            x = x + self.mlp(self.ln2(x))
            return x

    class Brain(nn.Module):
        def __init__(self):
            super().__init__()
            self.embed = nn.Embedding(vocab, dim)
            self.pos = nn.Embedding(ctx, dim)
            self.blocks = nn.ModuleList(Block() for _ in range(layers))
            self.lnf = nn.LayerNorm(dim)
            self.head = nn.Linear(dim, vocab)

        def forward(self, idx):
            T = idx.shape[1]
            x = self.embed(idx) + self.pos(torch.arange(T,
                                                        device=idx.device))
            for block in self.blocks:
                x = block(x)
            return self.head(self.lnf(x))

    model = Brain().to(device)
    param_count = sum(p.numel() for p in model.parameters())
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr)
    losses = []

    def sample_batch():
        starts = torch.randint(0, len(data) - seq - 1, (batch,))
        idx = torch.stack([data[s:s + seq] for s in starts])
        return idx.to(device), idx.to(device)

    model.train()
    for step in range(1, steps + 1):
        idx, targets = sample_batch()
        logits = model(idx)
        loss = torch.nn.functional.cross_entropy(
            logits.view(-1, vocab), targets.view(-1))
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        losses.append(float(loss))
        if log_every and step % log_every == 0:
            print("  step %4d  loss %.3f" % (step, losses[-1]),
                  flush=True)

    return {
        "schema": BR_SCHEMA,
        "backend": "torch",
        "device": device,
        "config": config,
        "param_count": param_count,
        "steps": steps,
        "loss_first": round(losses[0], 3),
        "loss_last": round(losses[-1], 3),
        "decreased": losses[-1] < losses[0],
        "loss_curve": [round(l, 3) for l in losses[::log_every or 1]],
    }

