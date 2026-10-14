"""Optional real-browser smoke coverage for the local workbench page."""

from __future__ import annotations

import json
import threading
from urllib.parse import urlsplit

import pytest

playwright_sync = pytest.importorskip("playwright.sync_api")
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import expect, sync_playwright

from ioc_rejudge.ui import build_server


def _json_response(route, payload):
    route.fulfill(
        status=200,
        content_type="application/json",
        body=json.dumps(payload, ensure_ascii=False),
    )


def test_workbench_browser_mobile_incremental_drop_and_plaintext_confirm(tmp_path):
    server, url = build_server(
        tmp_path / "key.json",
        tmp_path / "bundles",
        port=0,
        cache_dir=tmp_path / "cache",
        workbench_dir=tmp_path / "workbench",
        # Workbench panel is retired from the default task center; browser
        # coverage of the legacy panel requires the opt-in flag.
        legacy_workbench=True,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    rows = [
        {
            "result_id": f"browser-task-{index:06d}",
            "ioc": f"host-{index}.example.invalid",
            "conclusion": "待复核" if index % 2 else "失活有效",
            "disposition": "review" if index % 2 else "gray",
            "route": "standard",
            "review_suggestion": "必看" if index % 2 else "无需复核",
            "confidence": 0.5,
            "missing_required_providers": [],
            "provider_statuses": {"ioc_info": "success"},
            "retained_urls": [],
            "reason": "synthetic browser row",
        }
        for index in range(1, 61)
    ]
    try:
        with sync_playwright() as playwright:
            try:
                browser = playwright.chromium.launch(headless=True)
            except PlaywrightError as exc:
                pytest.skip(f"Chromium is not installed: {exc}")
            page = browser.new_page(viewport={"width": 390, "height": 844})
            page.route(
                "**/api/workbench/import*",
                lambda route: _json_response(
                    route,
                    {
                        "import_id": "browser-import",
                        "filename": "dropped.jsonl",
                        "size": 32,
                        "rows": 1,
                    },
                ),
            )

            def task_route(route):
                path = urlsplit(route.request.url).path
                if path == "/api/workbench/task":
                    _json_response(
                        route,
                        {
                            "task_id": "browser-task",
                            "import_id": "browser-import",
                            "state": "succeeded",
                            "result_count": len(rows),
                        },
                    )
                else:
                    route.continue_()

            page.route("**/api/workbench/task*", task_route)
            page.route(
                "**/api/workbench/results*",
                lambda route: _json_response(
                    route,
                    {
                        "task_id": "browser-task",
                        "state": "succeeded",
                        "total": len(rows),
                        "offset": 0,
                        "limit": 100,
                        "rows": rows,
                    },
                ),
            )
            page.route(
                "**/api/workbench/explanation*",
                lambda route: _json_response(
                    route,
                    {"result_id": "browser-task-000001", "explanation": "synthetic"},
                ),
            )

            page.goto(url)
            expect(page.locator("#workbench-panel")).to_be_visible()
            page.locator("#workbench-file").set_input_files(
                {
                    "name": "dropped.jsonl",
                    "mimeType": "application/json",
                    "buffer": b'{"ioc":"host.example.invalid"}\n',
                }
            )
            expect(page.locator("#workbench-file-status")).to_contain_text("dropped.jsonl")
            page.locator("#workbench-import").click()
            expect(page.locator("#workbench-start")).to_be_enabled()
            page.locator("#workbench-start").click()
            expect(page.locator("#workbench-results")).to_be_enabled()
            page.locator("#workbench-results").click()
            expect(page.locator("#workbench-results-result")).to_be_visible()
            expect(page.locator("#workbench-results-body")).to_have_attribute(
                "aria-busy", "false"
            )
            expect(page.locator("#workbench-results-body tr")).to_have_count(len(rows))
            assert page.locator("#workbench-results-body td[data-label='IOC']").first.is_visible()
            table_width = page.locator("table.workbench-results-table").bounding_box()["width"]
            assert table_width <= 390

            dialogs = []

            def dismiss_plaintext(dialog):
                dialogs.append(dialog.message)
                dialog.dismiss()

            page.once("dialog", dismiss_plaintext)
            # 脱敏协作面板在独立模式里；先切到该模式再验证明文二次确认。
            page.locator("#nav-share").click()
            page.locator("#lookup-output").evaluate(
                "(element) => { element.value = '{\"ioc\":\"secret.example.invalid\"}\\n'; element.closest('.result').hidden = false; }"
            )
            page.locator("#lookup-copy").click()
            assert dialogs and "明文" in dialogs[0]
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_queue_browser_mobile_flow_cards_and_export(tmp_path):
    """切片 7：390px 下粘贴→入队→运行→结果卡片→解释→复核→导出全流程。"""
    server, url = build_server(
        tmp_path / "key.json",
        tmp_path / "bundles",
        port=0,
        cache_dir=tmp_path / "cache",
        provider_env={},
        jobs_dir=tmp_path / "jobs",
        workbench_dir=tmp_path / "workbench",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    errors: list[str] = []
    try:
        with sync_playwright() as playwright:
            try:
                browser = playwright.chromium.launch(headless=True)
            except PlaywrightError as exc:
                pytest.skip(f"Chromium is not installed: {exc}")
            context = browser.new_context(
                viewport={"width": 390, "height": 844},
                accept_downloads=True,
            )
            page = context.new_page()
            page.on("pageerror", lambda exc: errors.append(str(exc)))
            page.on(
                "console",
                lambda msg: errors.append(msg.text) if msg.type == "error" else None,
            )
            page.goto(url, wait_until="networkidle")
            page.fill("#queue-paste", "alpha.example.invalid\nbeta.example.invalid\n")
            page.click("#queue-enqueue")
            page.wait_for_function(
                "() => document.querySelectorAll('#queue-list tr[data-job-id]').length === 1",
                timeout=20_000,
            )
            assert (
                page.locator("#queue-enqueue").bounding_box()["height"] >= 44
            ), "touch target must stay at least 44px on mobile"
            page.click("#queue-list [data-queue-run]")
            page.wait_for_function(
                "() => document.querySelector('#queue-list .state-chip')"
                ".textContent.includes('已完成')",
                timeout=90_000,
            )
            page.click("#queue-list [data-queue-results]")
            page.wait_for_function(
                "() => document.querySelectorAll('#queue-results-body tr.queue-row').length === 2",
                timeout=20_000,
            )
            layout = page.evaluate(
                """() => ({
                    rowDisplay: getComputedStyle(document.querySelector('#queue-results-body tr.queue-row')).display,
                    cellDisplay: getComputedStyle(document.querySelector('#queue-results-body td.cell-ioc')).display,
                    label: getComputedStyle(document.querySelector('#queue-results-body td.cell-ioc'), '::before').content,
                    scrollWidth: document.documentElement.scrollWidth,
                    clientWidth: document.documentElement.clientWidth,
                })"""
            )
            assert layout["rowDisplay"] == "block", layout
            assert layout["cellDisplay"] == "grid", layout
            assert "IOC" in layout["label"], layout
            assert layout["scrollWidth"] <= layout["clientWidth"] + 1, layout
            page.click("#queue-results-body tr.queue-row")
            page.wait_for_function(
                "() => !document.querySelector('#queue-detail-panel').hidden && "
                "document.querySelector('#queue-explain-viewer').innerText.length > 0",
                timeout=20_000,
            )
            panel_box = page.locator("#queue-detail-panel").bounding_box()
            assert panel_box["width"] >= 320, panel_box
            page.select_option("#queue-review-label", "approved")
            page.click("#queue-review-submit")
            page.wait_for_function(
                "() => Array.from(document.querySelectorAll('.toast')).some("
                "t => t.textContent.includes('系统结论未覆盖'))",
                timeout=15_000,
            )
            page.keyboard.press("Escape")
            page.wait_for_function(
                "() => document.querySelector('#queue-detail-panel').hidden", timeout=10_000
            )
            with page.expect_download(timeout=20_000) as download_info:
                page.click("#queue-export-menu-button")
                page.click("#queue-export-jsonl")
            assert download_info.value.suggested_filename.endswith(".jsonl")
            assert errors == [], errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
