# Owen Coder — Fine-tuned Code Model for Attestor

Fine-tunes Qwen2.5-Coder 3B on Attestor-verified code so it generates clean,
project-style Python without a cloud API.

## Requirements

- Python 3.10+
- 4GB+ VRAM (NVIDIA GPU)
- ~8GB disk for the base model + output

```
pip install "unsloth[colab-new]" datasets trl
```

## Steps

### 1. Extract training data

```
python training/extract_training_data.py
```

Produces `training_data.jsonl` — 1011 instruction-code pairs from the
Attestor codebase (functions, classes, modules with docstrings).

### 2. Fine-tune

```
python training/finetune.py
```

Runs QLoRA fine-tuning on Qwen2.5-Coder-3B-Instruct. Takes ~30-60 min
on a 4GB GPU. Outputs a LoRA adapter and a merged Q4_K_M GGUF.

### 3. Load into Ollama

```
cd training
ollama create owen-coder -f Modelfile
```

### 4. Use with Attestor

```
set OLLAMA_MODEL=owen-coder
python detector/forge.py "Write a secure file parser"
```

The model generates code → Attestor scans it → rejects bad output → loops.
