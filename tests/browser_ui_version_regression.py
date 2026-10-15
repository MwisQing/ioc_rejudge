"""Real-browser regression for the new/legacy UI version switch.

Exercises the version toggle in both pages at 1280px and 390px against a
temporary loopback server: bare URL defaults to new, the new-page toggle
navigates to the legacy page and the choice is remembered across reload,
the legacy-page toggle returns to new, localStorage memory drives the bare
URL, an explicit ``ui`` param never triggers a redirect, the token is
preserved and never leaks into the DOM, and there is no horizontal page
scroll at 390px.  Any console error or page error fails the run.
"""

from __future__ import annotations

import sys
import tempfile
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ioc_rejudge.ui import build_server

NEW_SELECTOR = "#theme-toggle"
LEGACY_TITLE = "（旧版）"


def _is_new(page) -> bool:
    return page.evaluate(f"() => !!document.querySelector('{NEW_SELECTOR}')") and not _has_legacy_title(page)


def _has_legacy_title(page) -> bool:
    return page.evaluate("() => document.title.includes(" + repr(LEGACY_TITLE) + ")")


def _is_legacy(page) -> bool:
    return _has_legacy_title(page) and not page.evaluate(f"() => !!document.querySelector('{NEW_SELECTOR}')")


def _assert_no_horizontal_scroll(page) -> None:
    layout = page.evaluate(
        "() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth })"
    )
    assert layout["sw"] <= layout["cw"] + 1, layout


def _assert_token_hidden(page, token: str) -> None:
    leaked = page.evaluate(
        "(t) => document.documentElement.innerHTML.includes(t) || document.body.innerText.includes(t)",
        token,
    )
    assert leaked is False, "token leaked into the DOM"


def _run_toggle_roundtrip(page, url: str, token: str) -> None:
    # 1. Bare URL defaults to the new page.
    page.goto(url, wait_until="networkidle")
    assert _is_new(page), "bare URL should render the new page"
    # 2. New-page toggle navigates to the legacy page.
    page.click("#ui-version-toggle")
    page.wait_for_load_state("networkidle")
    assert "ui=legacy" in page.url, page.url
    assert _is_legacy(page), "toggle should render the legacy page"
    _assert_token_hidden(page, token)
    # 3. Reload keeps the legacy page (memory + explicit param agree).
    page.reload(wait_until="networkidle")
    assert _is_legacy(page), "reload should stay on the legacy page"
    # 4. Legacy-page toggle returns to the new page.
    page.click("#ui-version-toggle")
    page.wait_for_load_state("networkidle")
    assert _is_new(page), "toggle should render the new page again"
    # 5. Reload keeps the new page.
    page.reload(wait_until="networkidle")
    assert _is_new(page), "reload should stay on the new page"


def _run_memory_cases(page, url: str, token: str) -> None:
    base = url.split("?token=")[0]
    # Memory=legacy on a bare URL redirects to the legacy page and keeps the token.
    page.add_init_script(
        "localStorage.setItem('ioc-rejudge-ui-version', 'legacy');"
    )
    page.goto(base + "?token=" + token, wait_until="networkidle")
    assert "ui=legacy" in page.url, page.url
    assert _is_legacy(page)
    assert token in page.url, "token must survive the memory redirect"
    page.evaluate("() => localStorage.removeItem('ioc-rejudge-ui-version')")
    # Memory=new on a bare URL stays on the new page with no ui param.
    page.add_init_script("localStorage.setItem('ioc-rejudge-ui-version', 'new');")
    page.goto(base + "?token=" + token, wait_until="networkidle")
    assert _is_new(page)
    assert "ui=" not in page.url, page.url
    page.evaluate("() => localStorage.removeItem('ioc-rejudge-ui-version')")
    # Invalid memory falls back to the new page.
    page.add_init_script("localStorage.setItem('ioc-rejudge-ui-version', 'bogus');")
    page.goto(base + "?token=" + token, wait_until="networkidle")
    assert _is_new(page)
    page.evaluate("() => localStorage.removeItem('ioc-rejudge-ui-version')")
    # An explicit ui param never triggers a redirect, even against memory.
    page.add_init_script("localStorage.setItem('ioc-rejudge-ui-version', 'legacy');")
    page.goto(base + "?token=" + token + "&ui=new", wait_until="networkidle")
    assert _is_new(page)
    assert page.url.endswith("ui=new"), page.url
    page.evaluate("() => localStorage.removeItem('ioc-rejudge-ui-version')")


def main() -> int:
    errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="ioc-ui-version-") as temp_root:
        root = Path(temp_root)
        server, url = build_server(
            root / "key.json",
            root / "bundles",
            port=0,
            cache_dir=root / "provider-cache",
            provider_env={},
            jobs_dir=root / "jobs",
            workbench_dir=root / "workbench",
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        token = parse_qs(urlsplit(url).query)["token"][0]
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                for width, height, mobile in ((1280, 900, False), (390, 844, True)):
                    context = browser.new_context(viewport={"width": width, "height": height})
                    page = context.new_page()
                    page.on(
                        "console",
                        lambda msg, w=width: errors.append(f"{w}:console:{msg.type}:{msg.text}")
                        if msg.type == "error"
                        else None,
                    )
                    page.on(
                        "pageerror",
                        lambda exc, w=width: errors.append(f"{w}:pageerror:{exc}"),
                    )
                    _run_toggle_roundtrip(page, url, token)
                    _run_memory_cases(page, url, token)
                    _assert_no_horizontal_scroll(page)
                    _assert_token_hidden(page, token)
                    print(f"{width}px ok")
                    context.close()
                browser.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    if errors:
        print("console/page errors:", errors)
        return 1
    print("browser ui version switch regression passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
