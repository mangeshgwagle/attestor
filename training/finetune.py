#!/usr/bin/env python3
"""Fine-tune Qwen2.5-Coder 3B on Attestor training data using QLoRA.

Requirements:
    pip install unsloth[colab-new] datasets trl

Runs on 4GB VRAM with unsloth's memory optimizations.
Produces a LoRA adapter, then merges and exports to GGUF for Ollama.
"""
import json
import os

TRAINING_DATA = os.path.join(os.path.dirname(__file__), "training_data.jsonl")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "owen-coder-lora")
MERGED_DIR = os.path.join(os.path.dirname(__file__), "owen-coder-merged")

BASE_MODEL = "Qwen/Qwen2.5-Coder-3B-Instruct"
MAX_SEQ_LENGTH = 2048
LORA_R = 16
LORA_ALPHA = 16
EPOCHS = 3
BATCH_SIZE = 1
GRAD_ACCUM = 4
LR = 2e-4


def load_data():
    rows = []
    with open(TRAINING_DATA, "r", encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            rows.append(row)
    return rows


ALPACA_TEMPLATE = """Below is an instruction that describes a task. Write a response that appropriately completes the request.

### Instruction:
{instruction}

### Response:
{output}"""


def format_row(row):
    return ALPACA_TEMPLATE.format(
        instruction=row["instruction"],
        output=row["output"],
    )


def main():
    from unsloth import FastLanguageModel
    from datasets import Dataset
    from trl import SFTTrainer
    from transformers import TrainingArguments

    print(f"Loading base model {BASE_MODEL} ...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=BASE_MODEL,
        max_seq_length=MAX_SEQ_LENGTH,
        dtype=None,  # auto-detect
        load_in_4bit=True,
    )

    model = FastLanguageModel.get_peft_model(
        model,
        r=LORA_R,
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
        lora_alpha=LORA_ALPHA,
        lora_dropout=0,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=42,
    )

    print("Loading training data ...")
    rows = load_data()
    print(f"  {len(rows)} examples")

    dataset = Dataset.from_list([{"text": format_row(r)} for r in rows])

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        dataset_text_field="text",
        max_seq_length=MAX_SEQ_LENGTH,
        dataset_num_proc=2,
        packing=False,
        args=TrainingArguments(
            per_device_train_batch_size=BATCH_SIZE,
            gradient_accumulation_steps=GRAD_ACCUM,
            warmup_steps=5,
            num_train_epochs=EPOCHS,
            learning_rate=LR,
            fp16=True,
            bf16=False,
            logging_steps=10,
            optim="adamw_8bit",
            seed=42,
            output_dir=OUTPUT_DIR,
            save_strategy="epoch",
        ),
    )

    print("Training ...")
    stats = trainer.train()
    print(f"Training loss: {stats.training_loss:.4f}")

    print(f"Saving LoRA adapter to {OUTPUT_DIR} ...")
    model.save_pretrained(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)

    print(f"Merging and exporting GGUF to {MERGED_DIR} ...")
    model.save_pretrained_gguf(
        MERGED_DIR,
        tokenizer,
        quantization_method="q4_k_m",
    )

    print("Done. To load in Ollama, create a Modelfile and run:")
    print(f"  ollama create owen-coder -f {MERGED_DIR}/Modelfile")


if __name__ == "__main__":
    main()
