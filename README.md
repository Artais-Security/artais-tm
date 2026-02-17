# Threat Model in a Box (tmib)

Generate a lightweight STRIDE-style threat model from a few CLI prompts.

## Install (dev)
python -m venv .venv && source .venv/bin/activate
pip install -e .

## Run
tmib

## Output
Writes a Markdown threat model to `./output/<project>-threat-model.md`.

## Extend
Edit `src/tmib/rules.py` to add new tailoring rules and threat rows.
