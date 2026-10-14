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
