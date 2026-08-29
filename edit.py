import sys
import requests

MODEL = "hf.co/JonathanColetti/Qwen3.8-27B-Uncensored-GGUF:Q4_K_M"
API_URL = "http://localhost:11434/api/generate"

def edit(filename, instruction):
    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        code = f.read()

    prompt = f"""You are an expert coder. Modify the following code strictly according to the instruction.
Return ONLY the full updated code within a single markdown code fence. Do not include commentary, explanations, or chatter.

Instruction: {instruction}

File: {filename}