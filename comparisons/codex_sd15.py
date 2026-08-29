#!/usr/bin/env python3
"""Stable Diffusion 1.5 text-to-image CLI using Hugging Face Diffusers.

Install:
    pip install -U torch diffusers transformers accelerate safetensors

Example:
    python codex_sd15.py "a cinematic photo of a glass castle at sunrise" --seed 7

Notes:
    - First run downloads the model from Hugging Face.
    - GPU is strongly recommended; CPU works but is very slow.
    - The model license and Hugging Face access rules still apply.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


DEFAULT_MODEL = "stable-diffusion-v1-5/stable-diffusion-v1-5"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI options for a deterministic SD 1.5 generation run."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prompt", help="text prompt for image generation")
    parser.add_argument("--negative-prompt", default="", help="things to avoid in the image")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Diffusers model id or local folder")
    parser.add_argument("--out", default="sd15_output.png", help="output PNG path")
    parser.add_argument("--seed", type=int, default=0, help="deterministic seed")
    parser.add_argument("--steps", type=int, default=30, help="denoising steps")
    parser.add_argument("--guidance", type=float, default=7.5, help="classifier-free guidance scale")
    parser.add_argument("--width", type=int, default=512, help="image width, usually multiple of 8")
    parser.add_argument("--height", type=int, default=512, help="image height, usually multiple of 8")
    parser.add_argument("--device", choices=("auto", "cuda", "mps", "cpu"), default="auto")
    parser.add_argument("--attention-slicing", action="store_true",
                        help="reduce memory use at the cost of speed")
    return parser.parse_args(argv)


def choose_device(requested: str) -> str:
    """Resolve auto/cuda/mps/cpu into a real usable PyTorch device name."""
    import torch

    if requested != "auto":
        if requested == "cuda" and not torch.cuda.is_available():
            raise RuntimeError("CUDA was requested, but torch.cuda.is_available() is false.")
        if requested == "mps" and not torch.backends.mps.is_available():
            raise RuntimeError("MPS was requested, but this PyTorch build cannot use MPS.")
        return requested
    if torch.cuda.is_available():
        return "cuda"
    if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():
        return "mps"
    return "cpu"


def validate_size(width: int, height: int) -> None:
    """Reject dimensions that SD pipelines cannot handle cleanly."""
    if width <= 0 or height <= 0:
        raise ValueError("width and height must be positive.")
    if width % 8 or height % 8:
        raise ValueError("Stable Diffusion dimensions should be multiples of 8.")
    if width * height > 1536 * 1536:
        raise ValueError("refusing a very large image; lower width/height first.")


def load_pipeline(model: str, device: str, attention_slicing: bool) -> object:
    """Load a Diffusers pipeline with a device-appropriate dtype."""
    import torch
    from diffusers import DiffusionPipeline

    dtype = torch.float16 if device == "cuda" else torch.float32
    pipe = DiffusionPipeline.from_pretrained(
        model,
        torch_dtype=dtype,
        use_safetensors=True,
    )
    if attention_slicing:
        pipe.enable_attention_slicing()
    pipe = pipe.to(device)
    return pipe


def generate_image(args: argparse.Namespace) -> Path:
    """Generate one image and return the saved PNG path."""
    import torch

    validate_size(args.width, args.height)
    device = choose_device(args.device)
    if device == "cpu":
        print("warning: CPU generation can take a long time.", file=sys.stderr)

    pipe = load_pipeline(args.model, device, args.attention_slicing)
    generator_device = "cuda" if device == "cuda" else "cpu"
    generator = torch.Generator(device=generator_device).manual_seed(args.seed)

    result = pipe(
        prompt=args.prompt,
        negative_prompt=args.negative_prompt or None,
        width=args.width,
        height=args.height,
        num_inference_steps=args.steps,
        guidance_scale=args.guidance,
        generator=generator,
    )
    image = result.images[0]
    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output)
    return output


def main(argv: list[str] | None = None) -> int:
    """Run the command-line program."""
    args = parse_args(argv)
    try:
        output = generate_image(args)
    except KeyboardInterrupt:
        print("cancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    print("wrote %s" % output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
