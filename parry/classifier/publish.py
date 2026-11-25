"""Stage and upload v1 (seed 1337) to the Hugging Face Hub.

The staged folder holds the trained weights and tokenizer unchanged, a config with readable
labels (BENIGN / INJECTION; weights untouched), `parry_calibration.json` (temperature,
threshold and chunking, copied from the committed results) and the model card as README.md.
The token is read from ~/.parry/keys.env (HF_TOKEN) and passed to the client, never shown.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from parry.classifier.card import CARD, RESULTS
from parry.classifier.chunking import OVERLAP
from parry.classifier.train import ARTIFACTS, DEFAULTS

SEED = "1337"
FILES = ("model.safetensors", "tokenizer.json", "tokenizer_config.json", "training.json")


def calibration() -> dict[str, Any]:
    ev = json.loads((RESULTS / "phase4-eval.json").read_text())
    s = ev["seeds"][SEED]
    return {
        "seed": int(SEED),
        "positive_label": 1,
        "window": DEFAULTS["max_len"],
        "overlap": OVERLAP,
        "aggregation": "max over windows",
        "temperature": s["temperature"],
        "threshold": s["threshold"],
        "target_val_fpr": ev["target_val_fpr"],
        "eval_git_commit": ev["git_commit"],
        "data_manifest_sha256": ev["data_manifest_sha256"],
    }


def stage(out: Path, repo_id: str) -> Path:
    src = ARTIFACTS / f"deberta-v3-small-seed{SEED}"
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for name in FILES:
        shutil.copy2(src / name, out / name)
    config = json.loads((src / "config.json").read_text())
    config["id2label"] = {"0": "BENIGN", "1": "INJECTION"}
    config["label2id"] = {"BENIGN": 0, "INJECTION": 1}
    (out / "config.json").write_text(json.dumps(config, indent=2) + "\n")
    (out / "parry_calibration.json").write_text(json.dumps(calibration(), indent=2) + "\n")
    (out / "README.md").write_text(CARD.read_text().replace("REPO_ID", repo_id))
    return out


def upload(folder: Path, repo_id: str, token: str) -> str:
    from huggingface_hub import HfApi

    api = HfApi(token=token)
    api.create_repo(repo_id, repo_type="model", exist_ok=True)
    info = api.upload_folder(
        folder_path=str(folder),
        repo_id=repo_id,
        repo_type="model",
        commit_message="Parry prompt-injection classifier v1 (seed 1337)",
    )
    return str(info.commit_url)
