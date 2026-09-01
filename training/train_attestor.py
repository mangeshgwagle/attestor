#!/usr/bin/env python3
"""Unified Attestor model training pipeline.

Merges ALL training data sources, then fine-tunes via QLoRA on either
the 3B or 14B Qwen coder model. Exports to GGUF for Ollama.

Pipeline:
  1. Generate SWE-bench pairs (if not cached)
  2. Fetch CVE pairs from GitHub+NVD (if not cached)
  3. Merge all sources with dedup
  4. Fine-tune with QLoRA
  5. Export to GGUF
  6. Create Ollama Modelfile

Usage:
    python train_attestor.py                     # full pipeline, 3B model
    python train_attestor.py --model 14b         # train on 14B abliterated
    python train_attestor.py --skip-fetch        # skip data fetching, use cached
    python train_attestor.py --data-only         # only generate/merge data, no training
    python train_attestor.py --colab             # print Colab notebook cells

Requires: pip install unsloth[colab-new] datasets trl
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import subprocess
import sys
import time
from collections import Counter

TRAINING_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_CONFIGS = {
    "3b": {
        "base_model": "Qwen/Qwen2.5-Coder-3B-Instruct",
        "max_seq_length": 4096,
        "lora_r": 64,
        "lora_alpha": 128,
        "lora_dropout": 0.05,
        "epochs": 6,
        "batch_size": 2,
        "grad_accum": 8,
        "lr": 1e-4,
        "output_name": "owen-coder",
    },
    "14b": {
        "base_model": "Qwen/Qwen2.5-Coder-14B-Instruct",
        "max_seq_length": 4096,
        "lora_r": 32,
        "lora_alpha": 64,
        "lora_dropout": 0.05,
        "epochs": 4,
        "batch_size": 1,
        "grad_accum": 16,
        "lr": 5e-5,
        "output_name": "owen-coder-14b",
    },
}

DATA_SOURCES = [
    ("training_data.jsonl", "original"),
    ("training_data_bulk.jsonl", "bulk"),
    ("training_data_expanded.jsonl", "expanded"),
    ("real_cve_pairs.jsonl", "real_cve"),
    ("swebench_training_data.jsonl", "swebench"),
    ("tool_use_training.jsonl", "tool_use"),
    ("pentagi_training_data.jsonl", "pentagi"),
]

TARGET_MODULES = [
    "q_proj", "k_proj", "v_proj", "o_proj",
    "gate_proj", "up_proj", "down_proj",
]

SYSTEM_PROMPT = (
    "You are a security analysis engine. You find vulnerabilities in source "
    "code with high precision. You report findings with specific CWE IDs, "
    "severity ratings, line numbers, and concrete fix suggestions. You never "
    "hallucinate vulnerabilities that don't exist."
)

CHAT_TEMPLATE = """<|im_start|>system
{system}<|im_end|>
<|im_start|>user
{instruction}<|im_end|>
<|im_start|>assistant
{output}<|im_end|>"""


def log(msg: str):
    print(f"  [{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def load_jsonl(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    pairs = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                pairs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return pairs


def step_generate_swebench(skip_if_exists: bool = True):
    out_path = os.path.join(TRAINING_DIR, "swebench_training_data.jsonl")
    if skip_if_exists and os.path.exists(out_path):
        count = sum(1 for _ in open(out_path))
        log(f"SWE-bench data exists ({count} pairs), skipping")
        return

    log("Generating SWE-bench training data...")
    script = os.path.join(TRAINING_DIR, "generate_swebench_data.py")
    subprocess.run(
        [sys.executable, script, "--limit", "500", "--filter", "python",
         "--out", out_path],
        cwd=TRAINING_DIR)


def step_fetch_cve(skip_if_exists: bool = True):
    out_path = os.path.join(TRAINING_DIR, "real_cve_pairs.jsonl")
    if skip_if_exists and os.path.exists(out_path):
        count = sum(1 for _ in open(out_path))
        if count > 100:
            log(f"CVE data exists ({count} pairs), skipping")
            return

    db_path = os.path.join(TRAINING_DIR, "CVEfixes.db")
    if os.path.exists(db_path):
        log("Extracting CVE pairs from CVEfixes.db...")
        script = os.path.join(TRAINING_DIR, "extract_cve_pairs.py")
        subprocess.run(
            [sys.executable, script, "--db", db_path, "--out", out_path],
            cwd=TRAINING_DIR)
    else:
        log("Fetching CVE data from GitHub+NVD (this takes a while)...")
        script = os.path.join(TRAINING_DIR, "fetch_real_cve_data.py")
        subprocess.run(
            [sys.executable, script, "--out", out_path,
             "--queries", "10", "--per-query", "20"],
            cwd=TRAINING_DIR)


def step_merge_data() -> str:
    log("Merging all training data sources...")
    all_pairs = []
    source_counts = {}

    for filename, tag in DATA_SOURCES:
        path = os.path.join(TRAINING_DIR, filename)
        pairs = load_jsonl(path)
        for p in pairs:
            p["_source"] = tag
        source_counts[tag] = len(pairs)
        all_pairs.extend(pairs)
        status = f"{len(pairs):5d} pairs" if pairs else "not found"
        log(f"  {filename:40s}: {status}")

    log(f"  Total before dedup: {len(all_pairs)}")
    seen = set()
    unique = []
    for p in all_pairs:
        key = hashlib.md5(p.get("instruction", "").strip().encode()).hexdigest()
        if key not in seen:
            seen.add(key)
            unique.append(p)

    log(f"  Total after dedup:  {len(unique)}")

    random.seed(42)
    random.shuffle(unique)

    merged_path = os.path.join(TRAINING_DIR, "training_data_merged.jsonl")
    with open(merged_path, "w", encoding="utf-8") as f:
        for p in unique:
            f.write(json.dumps({
                "instruction": p["instruction"],
                "output": p["output"],
            }, ensure_ascii=False) + "\n")

    size_mb = os.path.getsize(merged_path) / 1024 / 1024
    log(f"  Merged: {len(unique)} pairs ({size_mb:.1f} MB)")

    source_final = Counter(p.get("_source", "?") for p in unique)
    for tag, loaded in source_counts.items():
        kept = source_final.get(tag, 0)
        log(f"    {tag:15s}: {loaded:5d} loaded -> {kept:5d} kept")

    return merged_path


def step_train(data_path: str, model_size: str = "3b"):
    config = MODEL_CONFIGS[model_size]
    log(f"Training {config['base_model']} with QLoRA...")
    log(f"  LoRA r={config['lora_r']} alpha={config['lora_alpha']}")
    log(f"  {config['epochs']} epochs, LR={config['lr']}")
    log(f"  Effective batch size: {config['batch_size'] * config['grad_accum']}")

    from unsloth import FastLanguageModel
    from datasets import Dataset
    from trl import SFTTrainer
    from transformers import TrainingArguments

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=config["base_model"],
        max_seq_length=config["max_seq_length"],
        dtype=None,
        load_in_4bit=True,
    )

    model = FastLanguageModel.get_peft_model(
        model,
        r=config["lora_r"],
        target_modules=TARGET_MODULES,
        lora_alpha=config["lora_alpha"],
        lora_dropout=config["lora_dropout"],
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=42,
    )

    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total = sum(p.numel() for p in model.parameters())
    log(f"  Trainable: {trainable:,} / {total:,} ({100 * trainable / total:.1f}%)")

    rows = load_jsonl(data_path)
    log(f"  Training examples: {len(rows)}")

    def format_row(row):
        return CHAT_TEMPLATE.format(
            system=SYSTEM_PROMPT,
            instruction=row["instruction"],
            output=row["output"],
        )

    dataset = Dataset.from_list([{"text": format_row(r)} for r in rows])

    lora_dir = os.path.join(TRAINING_DIR, f"{config['output_name']}-lora")
    merged_dir = os.path.join(TRAINING_DIR, f"{config['output_name']}-merged")

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        dataset_text_field="text",
        max_seq_length=config["max_seq_length"],
        dataset_num_proc=2,
        packing=True,
        args=TrainingArguments(
            per_device_train_batch_size=config["batch_size"],
            gradient_accumulation_steps=config["grad_accum"],
            warmup_ratio=0.06,
            num_train_epochs=config["epochs"],
            learning_rate=config["lr"],
            lr_scheduler_type="cosine",
            weight_decay=0.01,
            fp16=True,
            bf16=False,
            logging_steps=5,
            optim="adamw_8bit",
            seed=42,
            output_dir=lora_dir,
            save_strategy="epoch",
            report_to="none",
        ),
    )

    log("  Training started...")
    t0 = time.time()
    stats = trainer.train()
    elapsed = time.time() - t0
    log(f"  Training loss: {stats.training_loss:.4f}")
    log(f"  Runtime: {elapsed:.0f}s ({elapsed/60:.1f}m)")

    log(f"  Saving LoRA to {lora_dir}...")
    model.save_pretrained(lora_dir)
    tokenizer.save_pretrained(lora_dir)

    log(f"  Exporting GGUF to {merged_dir}...")
    model.save_pretrained_gguf(
        merged_dir, tokenizer, quantization_method="q4_k_m")

    modelfile = os.path.join(merged_dir, "Modelfile")
    gguf_files = [f for f in os.listdir(merged_dir)
                  if f.endswith(".gguf")] if os.path.isdir(merged_dir) else []
    gguf_name = gguf_files[0] if gguf_files else f"{config['output_name']}.Q4_K_M.gguf"

    with open(modelfile, "w") as f:
        f.write(f'FROM ./{gguf_name}\n\n')
        f.write(f'SYSTEM """{SYSTEM_PROMPT}"""\n\n')
        f.write('PARAMETER temperature 0.1\n')
        f.write('PARAMETER top_p 0.9\n')
        f.write('PARAMETER num_ctx 4096\n')
        f.write('PARAMETER stop "<|im_end|>"\n')

    log(f"\n  Done. To load in Ollama:")
    log(f"    cd {merged_dir}")
    log(f"    ollama create {config['output_name']} -f Modelfile")

    return merged_dir


def print_colab_notebook(model_size: str = "14b"):
    config = MODEL_CONFIGS[model_size]
    print("""
# ============================================================
# CELL 1: Install dependencies
# ============================================================
!pip install -q "unsloth[colab-new]" datasets trl

# ============================================================
# CELL 2: Upload training_data_merged.jsonl to /content/
# ============================================================
from google.colab import files
uploaded = files.upload()  # upload training_data_merged.jsonl

# ============================================================
# CELL 3: Train
# ============================================================""")
    print(f"""
import json, time
from unsloth import FastLanguageModel
from datasets import Dataset
from trl import SFTTrainer
from transformers import TrainingArguments

BASE_MODEL = "{config['base_model']}"
MAX_SEQ = {config['max_seq_length']}
LORA_R = {config['lora_r']}
LORA_ALPHA = {config['lora_alpha']}

SYSTEM = (
    "You are a security analysis engine. You find vulnerabilities in source "
    "code with high precision. You report findings with specific CWE IDs, "
    "severity ratings, line numbers, and concrete fix suggestions."
)

TEMPLATE = '<|im_start|>system\\n{{system}}<|im_end|>\\n<|im_start|>user\\n{{instruction}}<|im_end|>\\n<|im_start|>assistant\\n{{output}}<|im_end|>'

rows = [json.loads(l) for l in open("training_data_merged.jsonl")]
print(f"{{len(rows)}} training examples")

model, tokenizer = FastLanguageModel.from_pretrained(
    BASE_MODEL, max_seq_length=MAX_SEQ, dtype=None, load_in_4bit=True)

model = FastLanguageModel.get_peft_model(
    model, r=LORA_R,
    target_modules=["q_proj","k_proj","v_proj","o_proj","gate_proj","up_proj","down_proj"],
    lora_alpha=LORA_ALPHA, lora_dropout=0.05, bias="none",
    use_gradient_checkpointing="unsloth", random_state=42)

dataset = Dataset.from_list([{{"text": TEMPLATE.format(
    system=SYSTEM, instruction=r["instruction"], output=r["output"])}} for r in rows])

trainer = SFTTrainer(
    model=model, tokenizer=tokenizer, train_dataset=dataset,
    dataset_text_field="text", max_seq_length=MAX_SEQ,
    dataset_num_proc=2, packing=True,
    args=TrainingArguments(
        per_device_train_batch_size={config['batch_size']},
        gradient_accumulation_steps={config['grad_accum']},
        warmup_ratio=0.06, num_train_epochs={config['epochs']},
        learning_rate={config['lr']}, lr_scheduler_type="cosine",
        weight_decay=0.01, fp16=True, bf16=False, logging_steps=5,
        optim="adamw_8bit", seed=42,
        output_dir="{config['output_name']}-lora",
        save_strategy="epoch", report_to="none"))

stats = trainer.train()
print(f"Loss: {{stats.training_loss:.4f}}")

# ============================================================
# CELL 4: Export GGUF and download
# ============================================================
model.save_pretrained_gguf("{config['output_name']}-merged", tokenizer,
                           quantization_method="q4_k_m")

import shutil
shutil.make_archive("{config['output_name']}-merged", "zip",
                    "{config['output_name']}-merged")
files.download("{config['output_name']}-merged.zip")
""")


def main():
    parser = argparse.ArgumentParser(
        description="Attestor model training pipeline")
    parser.add_argument("--model", choices=["3b", "14b"], default="3b",
                        help="model size (default: 3b)")
    parser.add_argument("--skip-fetch", action="store_true",
                        help="skip data fetching, use cached files")
    parser.add_argument("--data-only", action="store_true",
                        help="only generate/merge data, no training")
    parser.add_argument("--colab", action="store_true",
                        help="print Colab notebook cells instead of training")
    args = parser.parse_args()

    os.chdir(TRAINING_DIR)

    print(f"\n{'='*60}")
    print(f"  ATTESTOR MODEL TRAINING PIPELINE")
    print(f"  Model: {MODEL_CONFIGS[args.model]['base_model']}")
    print(f"{'='*60}\n")

    if args.colab:
        print_colab_notebook(args.model)
        return

    if not args.skip_fetch:
        step_generate_swebench()
        step_fetch_cve()

    data_path = step_merge_data()

    if args.data_only:
        log("Data-only mode, skipping training.")
        return

    step_train(data_path, args.model)


if __name__ == "__main__":
    main()
