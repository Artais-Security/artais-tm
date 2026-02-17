from __future__ import annotations
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from tmib.rules import build_model
from tmib.templates import render_markdown


@dataclass(frozen=True)
class Answers:
    project: str
    app_type: str
    data_sensitivity: str
    auth: str
    cloud: str
    internet_facing: bool
    stores_pii: bool


def _pick(prompt: str, options: list[str]) -> str:
    print(f"\n{prompt}")
    for i, opt in enumerate(options, 1):
        print(f"  {i}. {opt}")
    while True:
        choice = input("Select: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return options[int(choice) - 1]
        print("Invalid selection. Try again.")


def _yesno(prompt: str) -> bool:
    while True:
        v = input(f"{prompt} [y/n]: ").strip().lower()
        if v in ("y", "yes"):
            return True
        if v in ("n", "no"):
            return False
        print("Please enter y or n.")


def main() -> None:
    print("Threat Model in a Box (tmib)\n")

    project = input("Project name: ").strip() or "my-project"
    app_type = _pick("App type:", ["web", "api", "mobile", "desktop", "cli"])
    data_sensitivity = _pick("Data sensitivity:", ["public", "internal", "confidential", "regulated"])
    auth = _pick("Auth mechanism:", ["none", "sessions", "jwt", "oauth2/oidc", "api_key"])
    cloud = _pick("Hosting:", ["none/on-prem", "aws", "gcp", "azure", "multi"])
    internet_facing = _yesno("Internet-facing?")
    stores_pii = _yesno("Stores PII?")

    ans = Answers(
        project=project,
        app_type=app_type,
        data_sensitivity=data_sensitivity,
        auth=auth,
        cloud=cloud,
        internet_facing=internet_facing,
        stores_pii=stores_pii,
    )

    model = build_model(ans)
    md = render_markdown(ans, model, generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))

    out_dir = Path("output")
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / f"{project.lower().replace(' ', '-')}-threat-model.md"
    out_path.write_text(md, encoding="utf-8")

    print(f"\n✅ Wrote: {out_path}")
