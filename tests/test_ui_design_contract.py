"""Design contract for the redesigned operator page.

Slice 0 of the approved front-end redesign: lock the DOM ids, API endpoints
and single-file constraints that the visual redesign must preserve, before
any markup is rewritten.
"""

from pathlib import Path


UI_PATH = Path(__file__).parents[1] / "ioc_rejudge" / "ui.html"


def page_text():
    return UI_PATH.read_text(encoding="utf-8")


def test_design_contract_keeps_every_panel_and_queue_id():
    page = page_text()
    expected_ids = (
        "queue-panel",
        "queue-enqueue",
        "queue-list",
        "queue-kpi",
        "queue-review-submit",
        "queue-export-jsonl",
        "queue-export-csv",
        "queue-export-xlsx",
        "queue-diff",
        "queue-baseline-job",
        "workbench-panel",
        "key-panel",
        "lookup-panel",
        "create-panel",
        "restore-panel",
        "scan-panel",
    )
    for element_id in expected_ids:
        assert f'id="{element_id}"' in page, element_id


def test_design_contract_locks_api_endpoints():
    page = page_text()
    expected_endpoints = (
        "/api/status",
        "/api/ops/status",
        "/api/jobs/enqueue",
        "/api/jobs/import",
        "/api/jobs/list",
        "/api/jobs/status",
        "/api/jobs/results",
        "/api/jobs/run",
        "/api/jobs/cancel",
        "/api/jobs/prune",
        "/api/jobs/explain",
        "/api/jobs/review",
        "/api/jobs/export",
        "/api/jobs/diff",
        "/api/workbench/import",
        "/api/workbench/task",
        "/api/workbench/cancel",
        "/api/workbench/results",
        "/api/workbench/explanation",
        "/api/workbench/review",
        "/api/workbench/export",
        "/api/workbench/diff",
    )
    for endpoint in expected_endpoints:
        assert endpoint in page, endpoint


def test_design_contract_stays_single_file_without_external_resources():
    page = page_text()
    lowered = page.lower()
    assert lowered.count("<script") == 1
    assert "src=" not in lowered
    assert "@import" not in lowered
    assert "http://" not in lowered
    assert "https://" not in lowered


def test_design_contract_keeps_system_fonts_and_reduced_motion():
    page = page_text()
    assert '"PingFang SC", "Microsoft YaHei"' in page
    assert "prefers-reduced-motion: reduce" in page


def test_design_contract_keeps_legacy_workbench_hidden_by_default():
    page = page_text()
    assert (
        'id="workbench-panel" hidden' in page
        or 'id="workbench-panel"hidden' in page
        or 'hidden id="workbench-panel"' in page
    )
    assert 'id="nav-workbench"' in page
    assert "legacy_workbench" in page


def test_design_contract_keeps_queue_state_and_review_labels():
    page = page_text()
    assert "queueState.iocInfoEnabled ? 'online' : 'offline'" in page
    for label in ("approved", "rejected", "pending"):
        assert f'value="{label}"' in page


def test_design_contract_queue_input_and_task_list():
    page = page_text()
    # 切片 2：拖放导入、模式选择、唯一主按钮与任务列表进度条。
    assert 'id="queue-drop-zone"' in page
    assert 'id="queue-file"' in page
    assert 'accept=".txt,.csv,.jsonl,.xlsx"' in page
    assert 'id="queue-file-clear"' in page
    assert 'name="queue-mode"' in page
    assert "queue-mode-row" in page
    assert "queue-progress" in page
    assert "queue-progress-fill" in page
    assert "transform: scaleX(" in page
    assert "24MB" in page
    assert "showToast" in page
    assert 'id="toast-host"' in page
    assert "bindQueueDropZone" in page
    assert "queueImportFile" in page


def test_design_contract_responsive_and_accessibility():
    page = page_text()
    # 切片 7：390 结果表转卡片、44px 触控目标、aria-live、reduced-motion。
    assert "table.queue-results-table tbody tr" in page
    assert "table.queue-results-table tbody td::before" in page
    assert "content: attr(data-label)" in page
    for label in ("IOC", "结论 / 处置", "人工标签", "置信度", "来源", "保留 URL", "摘要"):
        assert f"dataset.label = '{label}'" in page, label
    assert "min-height: 44px" in page
    assert 'aria-live="polite"' in page
    assert "aria-busy" in page
    assert "prefers-reduced-motion: reduce" in page
    assert "transition-duration: .01ms" in page
    assert "QUEUE_RENDER_CHUNK_SIZE = 24" in page
    assert "renderVersion" in page
    assert "requestAnimationFrame(mount)" in page
    # 静态骨架屏与内联 SVG 图标系统（零外部资源）。
    assert "queueResultsSkeleton" in page
    assert "queueExplainSkeleton" in page
    assert "skeleton-block" in page
    assert 'id="icon-sprite"' in page
    assert 'id="icon-alert"' in page


def test_design_contract_ops_panel():
    page = page_text()
    # 切片 6：运维模式首块仍是 #statusbar，后接健康、缓存、历史与 legacy 状态。
    for element_id in (
        "ops-panel",
        "ops-refresh",
        "ops-state-line",
        "ops-blocks",
        "ops-server-stats",
        "ops-health",
        "ops-cache-stats",
        "ops-cache-toggle",
        "ops-cache-providers",
        "ops-history-stats",
        "ops-history-jobs",
        "ops-workbench-stats",
    ):
        assert f'id="{element_id}"' in page, element_id
    assert "loadOpsStatus" in page
    assert "renderOpsStatus" in page
    assert "aria-busy" in page
    assert "按 provider 展开" in page
    assert "legacy workbench" in page
    assert "不自动轮询" in page


def test_design_contract_detail_panel_and_dialogs():
    page = page_text()
    # 切片 4：解释 side panel、快捷键说明与确认对话框。
    for element_id in (
        "queue-detail-panel",
        "queue-detail-close",
        "queue-detail-prev",
        "queue-detail-next",
        "queue-detail-nav-status",
        "queue-explain-viewer",
        "queue-review-label",
        "queue-review-reviewer",
        "queue-review-note",
        "shortcuts-dialog",
        "shortcuts-close",
        "confirm-dialog",
        "confirm-cancel",
        "confirm-ok",
    ):
        assert f'id="{element_id}"' in page, element_id
    assert 'role="dialog"' in page
    assert 'aria-modal="true"' in page
    assert "setBackgroundInert" in page
    assert "trapFocus" in page
    assert "confirmDialog" in page
    assert "window.confirm" in page
    assert "openQueueDetail" in page
    assert "queueDetailNavigate" in page
    assert "queuePendingNavigate" in page
    assert "doQueueBatchReview" in page
    assert "data-queue-batch-review" in page
    # 快捷键：J/K、Enter、A/R/P、Ctrl+Enter、N、E、D、?、1-5、/
    assert "event.key === 'Enter'" in page
    assert "'ArrowDown'" in page
    assert "'ArrowUp'" in page
    assert "queueSetReviewLabel('approved')" in page
    assert "queueSetReviewLabel('rejected')" in page
    assert "queueSetReviewLabel('pending')" in page
    assert "queueApplyQuickFilter" in page
    assert "openShortcutsDialog" in page
    assert "queueDetailOpen()" in page
    assert "resolveConfirm(false)" in page
