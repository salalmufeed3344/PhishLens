"""Screenshot the PhishLens dev server: home, phishing result, legit
result, metrics page. Saves PNGs to hidden_files/previews/."""

import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PREVIEWS = Path.home() / "workspace/goals/small-hackathon-entries/hidden_files/previews"
BASE = "http://127.0.0.1:8000"

PHISH_URL = "http://paypal-secure-login.com/verify/account/update?session=8839201"
LEGIT_URL = "https://www.wikipedia.org/wiki/Phishing"


def wait_for_server(timeout=30):
    for _ in range(timeout * 2):
        try:
            urllib.request.urlopen(BASE + "/", timeout=2)
            return True
        except Exception:
            time.sleep(0.5)
    return False


def main():
    server = subprocess.Popen(
        [str(ROOT / ".venv/bin/python"), "manage.py", "runserver", "127.0.0.1:8000"],
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        if not wait_for_server():
            print("server did not come up")
            sys.exit(1)
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={"width": 1280, "height": 900})

            page.goto(BASE + "/", wait_until="networkidle")
            page.screenshot(path=str(PREVIEWS / "phishlens-01-home.png"))

            # Phishing result: fill the form and submit.
            page.fill('input[name="url"]', PHISH_URL)
            page.click('button[type="submit"]')
            page.wait_for_selector(".verdict-row", timeout=30000)
            page.screenshot(path=str(PREVIEWS / "phishlens-02-result-phishing.png"), full_page=True)

            # Legit result.
            page.goto(BASE + "/", wait_until="networkidle")
            page.fill('input[name="url"]', LEGIT_URL)
            page.click('button[type="submit"]')
            page.wait_for_selector(".verdict-row", timeout=30000)
            page.screenshot(path=str(PREVIEWS / "phishlens-03-result-legit.png"), full_page=True)

            # Metrics page.
            page.goto(BASE + "/metrics", wait_until="networkidle")
            page.screenshot(path=str(PREVIEWS / "phishlens-04-metrics.png"), full_page=True)
            browser.close()
        print("screenshots saved to", PREVIEWS)
    finally:
        server.terminate()
        server.wait(timeout=10)


if __name__ == "__main__":
    main()
