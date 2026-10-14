"""Real-browser regression for the redesigned operator page.

Runs the full queue flow (paste → enqueue → run → results → explain → review →
export) at 1280px and 390px against a temporary loopback server, checks for
JavaScript errors, horizontal page scroll, reduced-motion behaviour and
main-thread long tasks, and writes screenshots next to the working directory.
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


PASTE = "alpha.example.invalid\nbeta.example.invalid\nalpha.example.invalid\n"


def _exercise_flow(page, url: str, token: str, *, mobile: bool, screenshot: Path) -> None:
    page.goto(url, wait_until="networkidle")
    page.wait_for_function(
        "() => !document.querySelector('#meta-key-text').textContent.includes('加载中')",
        timeout=15_000,
    )
    # 粘贴 → 入队
    baseline = page.locator("#queue-list tr[data-job-id]").count()
    page.fill("#queue-paste", PASTE)
    page.click("#queue-enqueue")
    page.wait_for_function(
        "() => document.querySelector('#queue-enqueue-preview').textContent.includes('有效 2')",
        timeout=20_000,
    )
    page.wait_for_function(
        "(expected) => document.querySelectorAll('#queue-list tr[data-job-id]').length === expected",
        arg=baseline + 1,
        timeout=20_000,
    )
    # 运行
    page.click("#queue-list [data-queue-run]")
    page.wait_for_function(
        "() => document.querySelector('#queue-list .state-chip').textContent.includes('已完成')",
        timeout=90_000,
    )
    # 结果
    page.click("#queue-list [data-queue-results]")
    page.wait_for_function(
        "() => document.querySelectorAll('#queue-results-body tr.queue-row').length === 2",
        timeout=20_000,
    )
    assert "共 2 行" in page.locator("#queue-page-status").inner_text()
    # 筛选
    page.click('[data-queue-filter="review"]')
    page.wait_for_function(
        "() => document.querySelector('#queue-page-status').textContent.includes('共 ')",
        timeout=20_000,
    )
    page.click('[data-queue-filter="all"]')
    page.wait_for_function(
        "() => document.querySelectorAll('#queue-results-body tr.queue-row').length === 2",
        timeout=20_000,
    )
    # 解释 side panel
    page.click("#queue-results-body tr.queue-row")
    page.wait_for_function(
        "() => !document.querySelector('#queue-detail-panel').hidden && "
        "document.querySelector('#queue-explain-viewer').innerText.length > 0",
        timeout=20_000,
    )
    if mobile:
        box = page.locator("#queue-detail-panel").bounding_box()
        assert box["width"] >= 320, box
    # 复核
    page.select_option("#queue-review-label", "approved")
    page.fill("#queue-review-reviewer", "browser-redesign")
    page.click("#queue-review-submit")
    page.wait_for_function(
        "() => Array.from(document.querySelectorAll('.toast')).some("
        "t => t.textContent.includes('系统结论未覆盖'))",
        timeout=15_000,
    )
    page.keyboard.press("Escape")
    page.wait_for_function("() => document.querySelector('#queue-detail-panel').hidden", timeout=10_000)
    # 导出
    with page.expect_download(timeout=20_000) as download_info:
        page.click("#queue-export-menu-button")
        page.click("#queue-export-jsonl")
    assert download_info.value.suggested_filename.endswith(".jsonl")
    layout = page.evaluate(
        """(token) => ({
            scrollWidth: document.documentElement.scrollWidth,
            clientWidth: document.documentElement.clientWidth,
            tokenInDom: document.documentElement.innerHTML.includes(token),
            tokenInText: document.body.innerText.includes(token),
        })""",
        token,
    )
    assert layout["tokenInDom"] is False, layout
    assert layout["tokenInText"] is False, layout
    if mobile:
        assert layout["scrollWidth"] <= layout["clientWidth"] + 1, layout
        display = page.evaluate(
            "() => getComputedStyle(document.querySelector('#queue-results-body tr.queue-row')).display"
        )
        assert display == "block", display
        label = page.evaluate(
            "() => getComputedStyle(document.querySelector('#queue-results-body td.cell-ioc'), '::before').content"
        )
        assert "IOC" in label, label
    else:
        assert layout["scrollWidth"] <= layout["clientWidth"] + 1, layout
    page.screenshot(path=str(screenshot), full_page=False)


def main() -> int:
    errors: list[str] = []
    long_tasks: list[float] = []
    with tempfile.TemporaryDirectory(prefix="ioc-ui-redesign-") as temp_root:
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
                for width, height, mobile in (
                    (1280, 900, False),
                    (390, 844, True),
                ):
                    context = browser.new_context(
                        viewport={"width": width, "height": height},
                        accept_downloads=True,
                    )
                    page = context.new_page()
                    page.on(
                        "console",
                        lambda msg, w=width: errors.append(f"{w}:{msg.type}:{msg.text}")
                        if msg.type == "error"
                        else None,
                    )
                    page.on(
                        "pageerror",
                        lambda exc, w=width: errors.append(f"{w}:pageerror:{exc}"),
                    )
                    page.add_init_script(
                        """
                        window.__longTasks = [];
                        try {
                          new PerformanceObserver((list) => {
                            list.getEntries().forEach((entry) => window.__longTasks.push(entry.duration));
                          }).observe({entryTypes: ['longtask']});
                        } catch (err) {}
                        """
                    )
                    screenshot = Path.cwd() / f"ui_redesign_{width}.png"
                    _exercise_flow(page, url, token, mobile=mobile, screenshot=screenshot)
                    durations = page.evaluate("() => window.__longTasks || []")
                    long_tasks.extend(durations)
                    print(f"{width}px ok, screenshot: {screenshot}")
                    context.close()
                # reduced motion：无平滑过渡
                context = browser.new_context(
                    viewport={"width": 1280, "height": 900},
                    reduced_motion="reduce",
                )
                page = context.new_page()
                page.goto(url, wait_until="networkidle")
                duration = page.evaluate(
                    "() => getComputedStyle(document.querySelector('#queue-panel')).transitionDuration"
                )
                seconds = float(str(duration).rstrip("s").rstrip("m")) if duration else 0.0
                if "ms" in str(duration):
                    seconds = seconds / 1000.0
                assert seconds <= 0.001, duration
                page.evaluate("() => document.querySelector('#theme-toggle').click()")
                assert page.evaluate("() => document.documentElement.dataset.theme") == "light"
                page.evaluate("() => document.querySelector('#theme-toggle').click()")
                assert page.evaluate("() => document.documentElement.dataset.theme") == "dark"
                context.close()
                browser.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    if errors:
        print("console errors:", errors)
        return 1
    worst = max(long_tasks) if long_tasks else 0.0
    print(f"long tasks: count={len(long_tasks)} worst={worst:.1f}ms")
    if worst > 200:
        print("main-thread long task above 200ms budget")
        return 1
    print("browser ui redesign regression passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
