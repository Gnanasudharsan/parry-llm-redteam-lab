"""Download the pinned external datasets and base model listed in classifier/sources.yaml."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml

SOURCES = Path("classifier/sources.yaml")
EXTERNAL = Path("datasets/external")


def load_sources(path: Path = SOURCES) -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(path.read_text())
    return data


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(path: Path = SOURCES, out: Path = EXTERNAL) -> dict[str, Any]:
    """Download every pinned dataset file and the base model snapshot; write a lock file
    with each file's sha256."""
    from huggingface_hub import hf_hub_download, snapshot_download

    src = load_sources(path)
    lock: dict[str, Any] = {"datasets": {}, "models": {}}
    for d in src["datasets"]:
        dest = out / d["id"].replace("/", "__")
        files = {}
        for name in d["files"]:
            local = Path(
                hf_hub_download(
                    d["id"], name, repo_type="dataset", revision=d["revision"], local_dir=dest
                )
            )
            files[name] = {"sha256": _sha256(local), "bytes": local.stat().st_size}
        lock["datasets"][d["id"]] = {
            "revision": d["revision"],
            "license": d["license"],
            "files": files,
        }
    for m in src.get("models", []):
        snap = snapshot_download(
            m["id"],
            revision=m["revision"],
            allow_patterns=["*.json", "*.bin", "*.model", "*.txt"],
        )
        lock["models"][m["id"]] = {"revision": m["revision"], "license": m["license"], "path": snap}
    out.mkdir(parents=True, exist_ok=True)
    (out / "lock.json").write_text(json.dumps(lock, indent=2) + "\n")
    return lock
