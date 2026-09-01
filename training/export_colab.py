#!/usr/bin/env python3
"""Export a proper Colab .ipynb notebook for training owen-coder.

    python export_colab.py                    # 14b notebook (default)
    python export_colab.py --model 3b         # 3b notebook
    python export_colab.py --out my_notebook  # custom output name
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from train_attestor import MODEL_CONFIGS, SYSTEM_PROMPT, TARGET_MODULES


def _cell(source: str, cell_type: str = "code") -> dict:
    return {
        "cell_type": cell_type,
        "metadata": {},
        "source": [line + "\n" for line in source.rstrip("\n").split("\n")],
        **({"outputs": [], "execution_count": None} if cell_type == "code" else {}),
    }


def build_notebook(model_size: str = "14b") -> dict:
    config = MODEL_CONFIGS[model_size]
    model_name = config["base_model"]
    lora_r = config["lora_r"]
    lora_alpha = config["lora_alpha"]
    epochs = config["epochs"]
    batch_size = config["batch_size"]
    grad_accum = config["grad_accum"]
    lr = config["lr"]
    output_name = config["output_name"]
    seq_len = config["max_seq_length"]
    targets = json.dumps(TARGET_MODULES)

    cells = []

    cells.append(_cell(
        f"# Attestor -- Owen Coder Training ({model_size.upper()})\n"
        f"# *for AI's, by AI*\n\n"
        f"Fine-tune **{model_name}** on Attestor's security training data.\n"
        f"Produces a GGUF model ready for Ollama deployment.\n\n"
        f"**Config:** LoRA r={lora_r} alpha={lora_alpha}, "
        f"{epochs} epochs, lr={lr}, seq_len={seq_len}",
        cell_type="markdown"
    ))

    cells.append(_cell(
        "# Step 1: Install dependencies\n"
        "!pip install -q 'unsloth[colab-new]' datasets trl"
    ))

    cells.append(_cell(
        "# Step 2: Upload training data\n"
        "# Upload training_data_merged.jsonl (and optionally feedback_training_data.jsonl)\n"
        "from google.colab import files\n"
        "uploaded = files.upload()"
    ))

    cells.append(_cell(
        "# Step 3: Load and merge training data\n"
        "import json, os\n\n"
        "rows = []\n"
        "for fn in sorted(uploaded.keys()):\n"
        "    if fn.endswith('.jsonl'):\n"
        "        with open(fn) as f:\n"
        "            batch = [json.loads(l) for l in f if l.strip()]\n"
        "        rows.extend(batch)\n"
        "        print(f'  {fn}: {len(batch)} pairs')\n\n"
        "# Deduplicate\n"
        "import hashlib\n"
        "seen = set()\n"
        "unique = []\n"
        "for r in rows:\n"
        "    key = hashlib.md5(r['instruction'].strip().encode()).hexdigest()\n"
        "    if key not in seen:\n"
        "        seen.add(key)\n"
        "        unique.append(r)\n"
        "rows = unique\n"
        "print(f'\\nTotal: {len(rows)} unique training pairs')"
    ))

    cells.append(_cell(
        f"# Step 4: Load model with QLoRA\n"
        f"from unsloth import FastLanguageModel\n\n"
        f"BASE_MODEL = '{model_name}'\n"
        f"MAX_SEQ = {seq_len}\n\n"
        f"model, tokenizer = FastLanguageModel.from_pretrained(\n"
        f"    BASE_MODEL, max_seq_length=MAX_SEQ, dtype=None, load_in_4bit=True)\n\n"
        f"model = FastLanguageModel.get_peft_model(\n"
        f"    model, r={lora_r},\n"
        f"    target_modules={targets},\n"
        f"    lora_alpha={lora_alpha}, lora_dropout=0.05, bias='none',\n"
        f"    use_gradient_checkpointing='unsloth', random_state=42)\n\n"
        f"trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)\n"
        f"total = sum(p.numel() for p in model.parameters())\n"
        f"print(f'Trainable: {{trainable:,}} / {{total:,}} ({{100*trainable/total:.1f}}%)')"
    ))

    system_escaped = SYSTEM_PROMPT.replace("'", "\\'")
    cells.append(_cell(
        f"# Step 5: Format dataset\n"
        f"from datasets import Dataset\n\n"
        f"SYSTEM = '{system_escaped}'\n\n"
        f"TEMPLATE = '<|im_start|>system\\n{{system}}<|im_end|>\\n<|im_start|>user\\n{{instruction}}<|im_end|>\\n<|im_start|>assistant\\n{{output}}<|im_end|>'\n\n"
        f"dataset = Dataset.from_list([{{\n"
        f"    'text': TEMPLATE.format(\n"
        f"        system=SYSTEM,\n"
        f"        instruction=r['instruction'],\n"
        f"        output=r['output']\n"
        f"    )\n"
        f"}} for r in rows])\n\n"
        f"print(f'Dataset: {{len(dataset)}} examples')\n"
        f"print(f'Sample length: {{len(dataset[0][\"text\"])}} chars')"
    ))

    cells.append(_cell(
        f"# Step 6: Train\n"
        f"import time\n"
        f"from trl import SFTTrainer\n"
        f"from transformers import TrainingArguments\n\n"
        f"trainer = SFTTrainer(\n"
        f"    model=model, tokenizer=tokenizer, train_dataset=dataset,\n"
        f"    dataset_text_field='text', max_seq_length=MAX_SEQ,\n"
        f"    dataset_num_proc=2, packing=True,\n"
        f"    args=TrainingArguments(\n"
        f"        per_device_train_batch_size={batch_size},\n"
        f"        gradient_accumulation_steps={grad_accum},\n"
        f"        warmup_ratio=0.06, num_train_epochs={epochs},\n"
        f"        learning_rate={lr}, lr_scheduler_type='cosine',\n"
        f"        weight_decay=0.01, fp16=True, bf16=False,\n"
        f"        logging_steps=5, optim='adamw_8bit', seed=42,\n"
        f"        output_dir='{output_name}-lora',\n"
        f"        save_strategy='epoch', report_to='none'))\n\n"
        f"t0 = time.time()\n"
        f"stats = trainer.train()\n"
        f"elapsed = time.time() - t0\n"
        f"print(f'Loss: {{stats.training_loss:.4f}}')\n"
        f"print(f'Time: {{elapsed:.0f}}s ({{elapsed/60:.1f}}m)')"
    ))

    cells.append(_cell(
        f"# Step 7: Export GGUF\n"
        f"model.save_pretrained_gguf(\n"
        f"    '{output_name}-merged', tokenizer,\n"
        f"    quantization_method='q4_k_m')\n\n"
        f"# Create Modelfile for Ollama\n"
        f"import glob\n"
        f"gguf = glob.glob('{output_name}-merged/*.gguf')[0]\n"
        f"gguf_name = os.path.basename(gguf)\n\n"
        f"with open('{output_name}-merged/Modelfile', 'w') as f:\n"
        f"    f.write(f'FROM ./{{gguf_name}}\\n\\n')\n"
        f"    f.write(f'SYSTEM \\\"\\\"\\\"{system_escaped}\\\"\\\"\\\"\\n\\n')\n"
        f"    f.write('PARAMETER temperature 0.1\\n')\n"
        f"    f.write('PARAMETER top_p 0.9\\n')\n"
        f"    f.write('PARAMETER num_ctx {seq_len}\\n')\n"
        f"    f.write('PARAMETER stop \"<|im_end|>\"\\n')\n\n"
        f"print(f'GGUF exported: {{gguf}}')\n"
        f"print('Modelfile created')"
    ))

    cells.append(_cell(
        f"# Step 8: Download\n"
        f"import shutil\n"
        f"shutil.make_archive('{output_name}-merged', 'zip', '{output_name}-merged')\n"
        f"files.download('{output_name}-merged.zip')\n\n"
        f"print('\\n--- DEPLOYMENT ---')\n"
        f"print('1. Unzip {output_name}-merged.zip')\n"
        f"print('2. cd {output_name}-merged')\n"
        f"print('3. ollama create {output_name} -f Modelfile')\n"
        f"print('4. ollama run {output_name}')"
    ))

    cells.append(_cell(
        f"# Owen Coder is ready!\n"
        f"# Deploy with: `ollama create {output_name} -f Modelfile`\n"
        f"# Then run Attestor with the trained model for hybrid analysis.",
        cell_type="markdown"
    ))

    return {
        "nbformat": 4,
        "nbformat_minor": 0,
        "metadata": {
            "colab": {"provenance": [], "gpuType": "T4"},
            "kernelspec": {"name": "python3", "display_name": "Python 3"},
            "language_info": {"name": "python"},
            "accelerator": "GPU",
        },
        "cells": cells,
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Export Colab training notebook")
    parser.add_argument("--model", choices=["3b", "14b"], default="14b")
    parser.add_argument("--out", help="output filename (without .ipynb)")
    args = parser.parse_args()

    notebook = build_notebook(args.model)
    name = args.out or f"train_owen_coder_{args.model}"
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            f"{name}.ipynb")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(notebook, f, indent=2, ensure_ascii=False)
    print(f"  Notebook exported: {out_path}")
    print(f"  Upload to Google Colab and run all cells.")


if __name__ == "__main__":
    main()
