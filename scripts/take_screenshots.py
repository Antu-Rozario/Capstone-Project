"""Reproducible README screenshots of the dashboard and rating page (headless Chromium via Playwright).

Walks the demo story on the synthetic dataset: ranking -> investigation -> generate Case Summary ->
approve -> evaluation -> policy search, plus the blind rating page. It starts its own Streamlit
servers on spare ports with temporary review/case/rating folders, so it never writes to
data/reviews.json or the team's data/rating/ratings.json.

Run: .venv/bin/python scripts/take_screenshots.py            (needs Ollama for the gemma4 narrative)
     .venv/bin/python scripts/take_screenshots.py --llm none (template narrative, no Ollama)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "screenshots"
DASH_PORT, RATING_PORT = 8511, 8512
VIEWPORT = {"width": 1440, "height": 1300}


def start_streamlit(app: str, port: int, env: dict[str, str]) -> subprocess.Popen[bytes]:
    cmd = [sys.executable, "-m", "streamlit", "run", app, "--server.port", str(port), "--server.headless", "true"]
    proc = subprocess.Popen(cmd, cwd=ROOT, env={**os.environ, **env}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(120):
        try:
            if urllib.request.urlopen(f"http://localhost:{port}/_stcore/health", timeout=1).read() == b"ok":
                return proc
        except OSError:
            time.sleep(0.5)
    proc.terminate()
    raise RuntimeError(f"{app} did not start on port {port}")


def settle(page: Page, ms: int = 1500) -> None:
    """Wait until Streamlit has finished re-running and charts have drawn."""
    page.wait_for_timeout(300)
    page.wait_for_selector("[data-testid='stStatusWidget']", state="detached", timeout=180_000)
    page.wait_for_timeout(ms)


def tab(page: Page, label: str) -> None:
    page.get_by_role("tab", name=label).click()
    settle(page)


def shot(page: Page, name: str) -> None:
    path = OUT / f"{name}.png"
    page.screenshot(path=str(path))
    print(f"  saved {path.relative_to(ROOT)}")


def dashboard(page: Page) -> None:
    page.goto(f"http://localhost:{DASH_PORT}")
    page.get_by_text("Insider Threat File Access UEBA").first.wait_for(timeout=120_000)
    settle(page, 3000)
    shot(page, "01-ranking")

    tab(page, "🔎 Investigation")
    page.locator(".vega-embed").first.wait_for(timeout=60_000)
    settle(page, 2000)
    shot(page, "02-investigation")

    tab(page, "📝 Case & review")
    page.get_by_role("button", name="Generate case summary").click()
    page.get_by_text("Review status").first.wait_for(timeout=300_000)
    settle(page)
    shot(page, "03-case-summary")

    page.get_by_role("textbox", name="Reviewer name").fill("Demo Reviewer")
    page.get_by_role("textbox", name="Reviewer name").press("Enter")
    settle(page)
    page.get_by_text("approved", exact=True).first.click()
    page.get_by_role("textbox", name="Notes").fill("Line manager confirmed no project required this transfer volume.")
    page.get_by_role("button", name="Submit review").click()
    settle(page, 2000)
    if not page.get_by_text("Review decision").first.is_visible():
        tab(page, "📝 Case & review")
    page.get_by_text("Review decision").first.scroll_into_view_if_needed()
    settle(page, 800)
    shot(page, "04-approved")

    tab(page, "📈 Evaluation")
    shot(page, "05-evaluation")

    tab(page, "📚 Policy search")
    box = page.get_by_role("textbox", name="Ask the policy corpus")
    box.fill("who must approve restricting a person's access?")
    box.press("Enter")
    settle(page)
    page.locator("[data-testid='stExpander']:visible summary").first.click()
    settle(page, 800)
    shot(page, "06-policy-search")


def rating(page: Page) -> None:
    page.goto(f"http://localhost:{RATING_PORT}")
    page.get_by_text("Case Summary Rating").first.wait_for(timeout=60_000)
    page.get_by_role("textbox", name="Your name").fill("Demo Rater")
    page.get_by_role("textbox", name="Your name").press("Enter")
    settle(page)
    shot(page, "07-rating")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--llm", default="auto", help="auto | none | <ollama model> for the Case Summary narrative")
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        rating_dir = Path(tmp) / "rating"
        rating_dir.mkdir()
        # Copy the set (never the team's ratings), keeping synthetic items only: screenshots never show
        # CERT-derived user activity (CERT licence: describe results, don't reproduce the data).
        items = json.loads((ROOT / "data" / "rating" / "items.json").read_text())
        key = json.loads((ROOT / "data" / "rating" / "key.json").read_text())
        synthetic = [i for i in items if key[i["item_id"]]["dataset"].startswith("synthetic")]
        (rating_dir / "items.json").write_text(json.dumps(synthetic))
        (rating_dir / "key.json").write_text(json.dumps({i["item_id"]: key[i["item_id"]] for i in synthetic}))
        dash_env = {"UEBA_LLM": args.llm, "UEBA_REVIEWS": f"{tmp}/reviews.json", "UEBA_CASES_DIR": f"{tmp}/cases"}
        servers = [
            start_streamlit("src/ueba/app.py", DASH_PORT, dash_env),
            start_streamlit("src/ueba/rating_app.py", RATING_PORT, {"UEBA_RATING_DIR": str(rating_dir)}),
        ]
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch()
                page = browser.new_page(viewport=VIEWPORT, device_scale_factor=1)
                print("dashboard …")
                dashboard(page)
                print("rating page …")
                rating(page)
                browser.close()
        finally:
            for s in servers:
                s.terminate()


if __name__ == "__main__":
    main()
