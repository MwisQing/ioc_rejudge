"""Real-browser regression for the offline workbench UI.

This script uses only a temporary loopback server, a legacy snapshot fixture,
and Chromium. It never reads credentials or production/cache data.
"""

from __future__ import annotations

import tempfile
import threading
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ioc_rejudge.ui import build_server


SNAPSHOT = (
    '{"ioc":"test-malware.invalid","data":[{"key":"test-malware.invalid",'
    '"level":70,"source":["sample-base"],"family":["trojan-downloader"],'
    '"hash":[{"md5":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab","level":70,'
    '"time":"2026-07-15 10:00:00"}],"updatetime":"2026-07-20 08:00:00",'
    '"context":"test-malware.invalid associated with trojan activity"}]}\n'
)


def exercise_viewport(page, snapshot: str, *, mobile: bool) -> None:
    page.goto(page.url, wait_until="networkidle")
    page.set_input_files(
        "#workbench-file",
        {
            "name": "offline-snapshot.jsonl",
            "mimeType": "application/jsonl",
            "buffer": snapshot.encode("utf-8"),
        },
    )
    page.locator("#workbench-import").click()
    page.wait_for_function(
        "() => !document.querySelector('#workbench-start').disabled",
        timeout=10_000,
    )

    page.locator("#workbench-start").click()
    page.wait_for_function(
        "() => !document.querySelector('#workbench-results').disabled",
        timeout=30_000,
    )
    assert "失败" not in page.locator("#workbench-task-stats").inner_text()

    page.locator("#workbench-results").click()
    page.locator("#workbench-results-body tr").first.wait_for(timeout=10_000)
    assert "test-malware.invalid" in page.locator("#workbench-results-body").inner_text()
    assert "共 1 行" in page.locator("#workbench-page-status").inner_text()

    page.locator("#workbench-query").fill("trojan")
    page.locator("#workbench-results").click()
    page.wait_for_function(
        "() => document.querySelector('#workbench-results-stats').textContent.includes('关键字 trojan')",
        timeout=10_000,
    )
    assert "匹配 1 行" in page.locator("#workbench-results-stats").inner_text()

    page.locator("#workbench-filter-review").click()
    page.wait_for_function(
        "() => document.querySelector('#workbench-results-stats').textContent.includes('处置 review')",
        timeout=10_000,
    )
    assert "匹配 0 行" in page.locator("#workbench-results-stats").inner_text()
    page.locator("#workbench-filter-all").click()
    page.locator("#workbench-results-body tr").first.wait_for(timeout=10_000)

    page.locator("#workbench-results-body tr").first.click()
    page.wait_for_function(
        "() => !document.querySelector('#workbench-detail-result').hidden && "
        "document.querySelector('#workbench-detail-viewer').innerText.includes('test-malware.invalid')",
        timeout=10_000,
    )
    assert "test-malware.invalid" in page.locator("#workbench-detail-viewer").inner_text()
    page.locator("#workbench-reviewer").fill("browser-regression")
    page.locator("#workbench-reason").fill("offline browser regression")
    page.locator("#workbench-decision").select_option("approved")
    page.locator("#workbench-review").click()
    page.wait_for_function("() => !document.querySelector('#workbench-flash').hidden")
    assert "系统结论未覆盖" in page.locator("#workbench-flash").inner_text()

    page.locator("#workbench-diagnostics").click()
    page.wait_for_function("() => !document.querySelector('#workbench-diagnostics-result').hidden")
    assert "已加载诊断" in page.locator("#workbench-diagnostics-stats").inner_text()
    page.locator("#workbench-summary").click()
    page.wait_for_function("() => !document.querySelector('#workbench-summary-result').hidden")
    assert "已加载运行摘要" in page.locator("#workbench-summary-stats").inner_text()

    with page.expect_download(timeout=10_000) as download_info:
        page.locator("#workbench-export-format").select_option("jsonl")
        page.locator("#workbench-export").click()
    assert download_info.value.suggested_filename.endswith(".jsonl")

    if mobile:
        layout = page.evaluate(
            """() => ({
                scrollWidth: document.documentElement.scrollWidth,
                clientWidth: document.documentElement.clientWidth,
                rowDisplay: getComputedStyle(document.querySelector('#workbench-results-body tr')).display,
            })"""
        )
        assert layout["scrollWidth"] <= layout["clientWidth"] + 1, layout
        assert layout["rowDisplay"] == "block", layout


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ioc-ui-browser-") as temp_root:
        root = Path(temp_root)
        server, url = build_server(
            root / "key.json",
            root / "bundles",
            port=0,
            cache_dir=root / "provider-cache",
            provider_env={},
            workbench_dir=root / "workbench",
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                for viewport, mobile in (
                    ({"width": 1280, "height": 900}, False),
                    ({"width": 390, "height": 844}, True),
                ):
                    context = browser.new_context(
                        viewport=viewport,
                        accept_downloads=True,
                    )
                    page = context.new_page()
                    page.goto(url, wait_until="networkidle")
                    exercise_viewport(page, SNAPSHOT, mobile=mobile)
                    context.close()
                browser.close()
        finally:
            server.shutdown()
            server.server_close()
    print("browser workbench regression passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
