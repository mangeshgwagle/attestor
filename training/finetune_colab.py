#!/usr/bin/env python3
"""Owen Coder fine-tuning script for Google Colab (free T4 GPU).

Usage:
  1. Upload training_data.jsonl to Colab
  2. Run this script
  3. Download the GGUF from owen-coder-merged/

On Colab free tier (T4 16GB), training takes ~20 min for EXPERT config.
"""

# --- Install dependencies (run this cell first in Colab) ---
# !pip install -q "unsloth[colab-new]" datasets trl

import json
import os

# ============================================================
# EXPERT CONFIG: aggressive training for maximum code quality
# ============================================================
BASE_MODEL = "Qwen/Qwen2.5-Coder-3B-Instruct"
MAX_SEQ_LENGTH = 4096       # longer context for full modules
LORA_R = 64                 # higher rank = more capacity
LORA_ALPHA = 128            # 2x rank for stronger adaptation
LORA_DROPOUT = 0.05         # light regularization
EPOCHS = 6                  # more passes over the data
BATCH_SIZE = 2              # T4 can handle this
GRAD_ACCUM = 8              # effective batch = 16
LR = 1e-4                   # lower LR for more stable expert training
WARMUP_RATIO = 0.06         # gradual warmup
WEIGHT_DECAY = 0.01         # prevent overfitting
LR_SCHEDULER = "cosine"     # smooth decay
TRAINING_DATA = "training_data.jsonl"
OUTPUT_DIR = "owen-coder-lora"
MERGED_DIR = "owen-coder-merged"
GGUF_QUANT = "q4_k_m"

# Target ALL linear layers for maximum adaptation
TARGET_MODULES = [
    "q_proj", "k_proj", "v_proj", "o_proj",
    "gate_proj", "up_proj", "down_proj",
    "lm_head",
]

# ============================================================
# Prompt format — Attestor engineering style
# ============================================================
SYSTEM_PROMPT = (
    "You are Owen Coder, a code generation engine trained on "
    "Attestor-verified Python. You write clean, secure, deterministic code. "
    "You never use network access, shell execution, subprocess, eval, or "
    "exec. You handle edge cases, validate inputs at boundaries, and prefer "
    "the standard library. Every function you write passes static analysis."
)

CHAT_TEMPLATE = """<|im_start|>system
{system}<|im_end|>
<|im_start|>user
{instruction}<|im_end|>
<|im_start|>assistant
{output}<|im_end|>"""


def load_data():
    rows = []
    with open(TRAINING_DATA, "r", encoding="utf-8") as f:
        for line in f:
            rows.append(json.loads(line))
    return rows


def format_row(row):
    return CHAT_TEMPLATE.format(
        system=SYSTEM_PROMPT,
        instruction=row["instruction"],
        output=row["output"],
    )


def main():
    from unsloth import FastLanguageModel
    from datasets import Dataset
    from trl import SFTTrainer
    from transformers import TrainingArguments

    print(f"=== OWEN CODER EXPERT TRAINING ===")
    print(f"Base model:  {BASE_MODEL}")
    print(f"LoRA rank:   {LORA_R}")
    print(f"LoRA alpha:  {LORA_ALPHA}")
    print(f"Epochs:      {EPOCHS}")
    print(f"Eff. batch:  {BATCH_SIZE * GRAD_ACCUM}")
    print(f"LR:          {LR}")
    print(f"Seq length:  {MAX_SEQ_LENGTH}")
    print()

    # Load base model in 4-bit
    print("Loading base model ...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=BASE_MODEL,
        max_seq_length=MAX_SEQ_LENGTH,
        dtype=None,
        load_in_4bit=True,
    )

    # Apply LoRA to all linear layers
    print("Applying LoRA adapters ...")
    model = FastLanguageModel.get_peft_model(
        model,
        r=LORA_R,
        target_modules=TARGET_MODULES,
        lora_alpha=LORA_ALPHA,
        lora_dropout=LORA_DROPOUT,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=42,
    )

    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total = sum(p.numel() for p in model.parameters())
    print(f"Trainable: {trainable:,} / {total:,} ({100 * trainable / total:.1f}%)")

    # Load and format training data
    print("Loading training data ...")
    rows = load_data()
    print(f"  {len(rows)} examples")

    dataset = Dataset.from_list([{"text": format_row(r)} for r in rows])

    # Verify a sample
    sample = dataset[0]["text"]
    tokens = tokenizer(sample, return_tensors="pt")
    print(f"  Sample token length: {tokens['input_ids'].shape[1]}")

    # Train
    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        dataset_text_field="text",
        max_seq_length=MAX_SEQ_LENGTH,
        dataset_num_proc=2,
        packing=True,  # pack short examples together for efficiency
        args=TrainingArguments(
            per_device_train_batch_size=BATCH_SIZE,
            gradient_accumulation_steps=GRAD_ACCUM,
            warmup_ratio=WARMUP_RATIO,
            num_train_epochs=EPOCHS,
            learning_rate=LR,
            lr_scheduler_type=LR_SCHEDULER,
            weight_decay=WEIGHT_DECAY,
            fp16=True,
            bf16=False,
            logging_steps=5,
            optim="adamw_8bit",
            seed=42,
            output_dir=OUTPUT_DIR,
            save_strategy="epoch",
            report_to="none",
        ),
    )

    print()
    print("Training started ...")
    stats = trainer.train()
    print(f"Training loss: {stats.training_loss:.4f}")
    print(f"Runtime: {stats.metrics['train_runtime']:.0f}s")

    # Save LoRA
    print(f"Saving LoRA adapter to {OUTPUT_DIR} ...")
    model.save_pretrained(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)

    # Merge and export GGUF
    print(f"Merging and exporting GGUF ({GGUF_QUANT}) ...")
    model.save_pretrained_gguf(
        MERGED_DIR,
        tokenizer,
        quantization_method=GGUF_QUANT,
    )

    # Test generation
    print()
    print("=== TEST GENERATION ===")
    FastLanguageModel.for_inference(model)
    test_prompt = CHAT_TEMPLATE.format(
        system=SYSTEM_PROMPT,
        instruction="Write a Python function: Validate an email address and return True if valid.",
        output="",
    ).rsplit("<|im_end|>", 1)[0]  # remove last end token so model generates

    inputs = tokenizer(test_prompt, return_tensors="pt").to("cuda")
    outputs = model.generate(**inputs, max_new_tokens=512, temperature=0.3, top_p=0.9)
    result = tokenizer.decode(outputs[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
    print(result)

    print()
    print("=== DONE ===")
    print(f"GGUF file: {MERGED_DIR}/")
    print("Download it, then on your machine:")
    print(f"  cd D:\\Owen 4.2\\Attestor 4.2\\training")
    print(f"  ollama create owen-coder -f Modelfile")


if __name__ == "__main__":
    main()
