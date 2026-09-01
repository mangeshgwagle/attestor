"""Tests for Colab notebook export."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "training"))
import export_colab


def test_build_notebook_structure():
    nb = export_colab.build_notebook("3b")
    assert nb["nbformat"] == 4
    assert "cells" in nb
    assert "metadata" in nb
    assert len(nb["cells"]) >= 8


def test_build_notebook_14b():
    nb = export_colab.build_notebook("14b")
    cells_text = " ".join(
        "".join(c["source"]) for c in nb["cells"]
    )
    assert "14B" in cells_text or "14b" in cells_text
    assert "owen-coder-14b" in cells_text


def test_build_notebook_3b():
    nb = export_colab.build_notebook("3b")
    cells_text = " ".join(
        "".join(c["source"]) for c in nb["cells"]
    )
    assert "3B" in cells_text or "3b" in cells_text
    assert "owen-coder" in cells_text


def test_notebook_has_markdown_and_code():
    nb = export_colab.build_notebook("14b")
    types = [c["cell_type"] for c in nb["cells"]]
    assert "markdown" in types
    assert "code" in types


def test_code_cells_have_outputs():
    nb = export_colab.build_notebook("14b")
    for c in nb["cells"]:
        if c["cell_type"] == "code":
            assert "outputs" in c
            assert "execution_count" in c


def test_notebook_valid_json():
    nb = export_colab.build_notebook("14b")
    serialized = json.dumps(nb)
    reparsed = json.loads(serialized)
    assert reparsed["nbformat"] == 4


def test_notebook_has_gpu():
    nb = export_colab.build_notebook("14b")
    assert nb["metadata"]["colab"]["gpuType"] == "T4"
    assert nb["metadata"]["accelerator"] == "GPU"


def test_notebook_has_unsloth_install():
    nb = export_colab.build_notebook("14b")
    code_sources = [
        "".join(c["source"]) for c in nb["cells"]
        if c["cell_type"] == "code"
    ]
    assert any("unsloth" in s for s in code_sources)


def test_notebook_has_gguf_export():
    nb = export_colab.build_notebook("14b")
    code_sources = [
        "".join(c["source"]) for c in nb["cells"]
        if c["cell_type"] == "code"
    ]
    assert any("gguf" in s.lower() or "GGUF" in s for s in code_sources)


def test_notebook_has_modelfile():
    nb = export_colab.build_notebook("14b")
    code_sources = [
        "".join(c["source"]) for c in nb["cells"]
        if c["cell_type"] == "code"
    ]
    assert any("Modelfile" in s for s in code_sources)


def test_notebook_has_system_prompt():
    nb = export_colab.build_notebook("14b")
    all_text = " ".join("".join(c["source"]) for c in nb["cells"])
    assert "security analysis engine" in all_text


def test_notebook_branding():
    nb = export_colab.build_notebook("14b")
    all_text = " ".join("".join(c["source"]) for c in nb["cells"])
    assert "for AI" in all_text


def test_cell_helper():
    cell = export_colab._cell("print('hello')", "code")
    assert cell["cell_type"] == "code"
    assert cell["outputs"] == []
    assert "print('hello')\n" in cell["source"]


def test_cell_markdown():
    cell = export_colab._cell("# Title", "markdown")
    assert cell["cell_type"] == "markdown"
    assert "outputs" not in cell


def test_export_writes_file():
    nb = export_colab.build_notebook("3b")
    with tempfile.NamedTemporaryFile(suffix=".ipynb", delete=False, mode="w") as f:
        json.dump(nb, f)
        path = f.name
    try:
        with open(path) as f:
            loaded = json.load(f)
        assert loaded["nbformat"] == 4
    finally:
        os.unlink(path)
