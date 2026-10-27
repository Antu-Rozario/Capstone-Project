"""Render docs/architecture.mmd (Mermaid) to docs/architecture.png with headless Chromium.

Edit the .mmd file, then run: .venv/bin/python scripts/render_architecture.py
Needs internet once per run to load Mermaid from the jsDelivr CDN.
"""

from __future__ import annotations

import json
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
SOURCE, OUT = ROOT / "docs" / "architecture.mmd", ROOT / "docs" / "architecture.png"

PAGE = """<!doctype html><html><head><meta charset="utf-8">
<style>body{margin:0;background:#fff;font-family:Helvetica,Arial,sans-serif} #d{display:inline-block;padding:24px}</style>
<script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script></head>
<body><div id="d"></div><script>
mermaid.initialize({startOnLoad:false, theme:"default", flowchart:{curve:"basis", htmlLabels:true}});
mermaid.render("arch", %s).then(r => { document.getElementById("d").innerHTML = r.svg; document.body.dataset.done = "1"; });
</script></body></html>"""


def main() -> None:
    html = PAGE % json.dumps(SOURCE.read_text())
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 2200, "height": 1200}, device_scale_factor=2)
        page.set_content(html)
        page.wait_for_selector("body[data-done='1']", timeout=60_000)
        page.locator("#d").screenshot(path=str(OUT))
        browser.close()
    print(f"saved {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
