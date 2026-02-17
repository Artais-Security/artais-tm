from tmib.rules import build_model
from tmib.templates import render_markdown

class Dummy:
    project="Demo"
    app_type="api"
    data_sensitivity="confidential"
    auth="jwt"
    cloud="aws"
    internet_facing=True
    stores_pii=True

def test_markdown_renders():
    model = build_model(Dummy)
    md = render_markdown(Dummy, model, "2026-02-17 00:00 UTC")
    assert "# Threat Model: Demo" in md
    assert "| STRIDE | Threat |" in md
    assert "## Security checklist" in md
