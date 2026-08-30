# Attestor model weights (drop-zone)

This is where Attestor's **embedded brain** lives. Put a GGUF model file here and
Attestor runs it **in-process** (via `local_model.py` + llama-cpp-python) — no
Ollama, no server, no network.

## How to put weights in Attestor

**Option A — drop a file here (auto-loaded):**
```
detector/models/your-model.gguf
```
Attestor loads the first `*.gguf` it finds in this folder.

**Option B — point at a file anywhere:**
```bash
export ATTESTOR_MODEL=/abs/path/to/model.gguf     # Linux/WSL
$env:ATTESTOR_MODEL="C:\path\to\model.gguf"       # PowerShell
```

## Getting a GGUF

- **Now (works immediately):** any small open instruct/coder GGUF, e.g.
  `Qwen2.5-Coder-3B-Instruct` q4_K_M (~2 GB). Download the `.gguf` and drop it here.
- **Later (your model):** the **Owen Coder** GGUF your Colab/Kaggle notebooks export
  — same filename convention, drop it here and Attestor uses it instead. Same code,
  better brain.

## Install the runtime
```bash
pip install "attestor[ai]"        # pulls llama-cpp-python
# or directly:
pip install llama-cpp-python
```

## Check it's wired up
```bash
python detector/local_model.py           # prints READY / what's missing
attestor audit some_file.py              # now uses the embedded model
```

## Notes
- GGUF files are **git-ignored** (they're large) — they live on disk, not in the repo.
- CPU works out of the box. For GPU, set `ATTESTOR_MODEL_GPU_LAYERS=35` (or however
  many layers fit your VRAM) and install a CUDA/Metal build of llama-cpp-python.
- Context size: `ATTESTOR_MODEL_CTX=8192` to widen it (uses more RAM).
