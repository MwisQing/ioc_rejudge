from pathlib import Path


UI_PATH = Path(__file__).parents[1] / "ioc_rejudge" / "ui.html"


def page_text():
    return UI_PATH.read_text(encoding="utf-8")


def test_workbench_markup_has_every_p0_control():
    page = page_text()
    assert 'id="statusbar"' in page
    assert 'href="#workbench-panel"' in page
    assert 'href="#create-panel"' in page
    assert 'href="#statusbar"' in page
    expected_ids = {
        "workbench-file",
        "workbench-drop-zone",
        "workbench-file-status",
        "workbench-import",
        "workbench-start",
        "workbench-refresh",
        "workbench-cancel",
        "workbench-dispositions",
        "workbench-query",
        "workbench-quick-filters",
        "workbench-filter-all",
        "workbench-filter-block",
        "workbench-filter-review",
        "workbench-filter-gray",
        "workbench-filter-false-positive",
        "workbench-filter-provider-issues",
        "workbench-provider-filter-status",
        "workbench-results",
        "workbench-prev-page",
        "workbench-page-status",
        "workbench-next-page",
        "workbench-diagnostics",
        "workbench-diagnostics-result",
        "workbench-diagnostics-viewer",
        "workbench-summary",
        "workbench-summary-result",
        "workbench-summary-stats",
        "workbench-summary-viewer",
        "workbench-baseline-task",
        "workbench-diff",
        "workbench-diff-result",
        "workbench-diff-viewer",
        "workbench-export-format",
        "workbench-export-preview",
        "workbench-export",
        "workbench-results-body",
        "workbench-detail-viewer",
        "workbench-detail-navigation",
        "workbench-prev-result",
        "workbench-detail-nav-status",
        "workbench-next-result",
        "workbench-decision",
        "workbench-reviewer",
        "workbench-reason",
        "workbench-review",
    }
    for element_id in expected_ids:
        assert f'id="{element_id}"' in page


def test_workbench_wires_all_api_routes_and_controls():
    page = page_text()
    expected_endpoints = {
        "/api/workbench/import",
        "/api/workbench/task",
        "/api/workbench/task/",
        "/api/workbench/cancel",
        "/api/workbench/results",
        "/api/workbench/explanation",
        "/api/workbench/review",
        "/api/workbench/export",
        "/api/workbench/export/",
        "/api/workbench/task/",
        "/diagnostics",
        "/summary",
        "/api/workbench/diff",
        "/download?token=",
    }
    for endpoint in expected_endpoints:
        assert endpoint in page

    listeners = {
        "workbench-import": "doWorkbenchImport",
        "workbench-start": "doWorkbenchStart",
        "workbench-refresh": "doWorkbenchRefresh",
        "workbench-cancel": "doWorkbenchCancel",
        "workbench-results": "loadWorkbenchResults",
        "workbench-review": "doWorkbenchReview",
        "workbench-export": "doWorkbenchExport",
    }
    for element_id, handler in listeners.items():
        assert f"$('{element_id}').addEventListener('click', {handler})" in page


def test_workbench_contract_keeps_unavailable_and_review_boundaries_visible():
    page = page_text()
    assert "err.unavailable" in page
    assert "workbenchSetAvailability" in page
    assert "系统结论未覆盖" in page
    assert "workbenchStateLabel" in page
    assert "succeeded" in page
    assert "failed" in page
    assert "cancelled" in page
    assert "running" in page
    assert "withBusy(button" in page

    # The browser must use the opaque export id download route, never the
    # backend's local path returned in an export response.
    assert "result.path" not in page
    assert "result.export_id" in page
    assert "unavailable" in page


def test_workbench_contract_covers_pagination_formats_and_navigation():
    page = page_text()
    assert 'data-workbench-disposition="block"' in page
    assert 'data-workbench-disposition="review"' in page
    assert 'data-workbench-disposition="gray"' in page
    assert 'data-workbench-disposition="false_positive"' in page
    assert 'offset: offset' in page
    assert 'limit: workbenchState.resultLimit' in page
    assert 'result.total' in page
    assert "workbench-prev-page" in page
    assert "workbench-next-page" in page
    assert "workbench-prev-result" in page
    assert "workbench-next-result" in page
    assert "workbench-export-format" in page
    assert "format: format" in page
    assert "encodeURIComponent(result.export_id)" in page
    assert "options: {background: true}" in page
    assert "workbenchScheduleRefresh" in page
    assert "loadWorkbenchDiagnostics" in page
    assert "loadWorkbenchSummary" in page
    assert "loadWorkbenchDiff" in page
    assert "workbenchSafeSummary" in page
    assert "selectedFile" in page
    assert "dataTransfer.files" in page
    assert "workbenchSelectFile" in page
    assert "workbench-drop-zone').addEventListener('drop', workbenchHandleDrop)" in page
    assert "workbench-file').addEventListener('change'" in page
    assert "window.confirm" in page
    assert "doLookupPlainCopy" in page
    assert "doRestorePlainCopy" in page
    assert "restore-copy').addEventListener('click', doRestorePlainCopy)" in page
    assert "force: force" in page
    assert "review_suggestion" in page
    assert "missing_required_providers" in page
    assert "provider_statuses" in page
    assert "retained_urls" in page
    assert "provider_issues" in page
    assert "applyWorkbenchProviderFilter" in page
    assert "baseline_task_id" in page
    for export_format in ("jsonl", "csv", "xlsx", "diagnostics", "diff", "bundle"):
        assert f'value="{export_format}"' in page

    listeners = {
        "workbench-prev-page": "loadWorkbenchPage(-1)",
        "workbench-next-page": "loadWorkbenchPage(1)",
        "workbench-diagnostics": "loadWorkbenchDiagnostics",
        "workbench-summary": "loadWorkbenchSummary",
        "workbench-diff": "loadWorkbenchDiff",
        "workbench-prev-result": "navigateWorkbenchResult(-1)",
        "workbench-next-result": "navigateWorkbenchResult(1)",
    }
    for element_id, call in listeners.items():
        assert (
            f"$('{element_id}').addEventListener('click', {call})" in page
            or f"$('{element_id}').addEventListener('click', () => {call})" in page
        )


def test_workbench_results_support_mobile_cards_and_incremental_rendering():
    page = page_text()
    assert 'class="workbench-results-table"' in page
    assert '@media (max-width: 719px)' in page
    assert 'table.workbench-results-table tbody tr' in page
    assert 'content: attr(data-label)' in page
    assert "td.dataset.label = item.label" in page
    assert 'WORKBENCH_RENDER_CHUNK_SIZE = 24' in page
    assert 'document.createDocumentFragment()' in page
    assert 'scheduleWorkbenchRender(appendChunk)' in page
    assert 'renderVersion' in page
    assert "body.setAttribute('aria-busy', 'true')" in page
    assert 'await renderWorkbenchRows(workbenchState.resultRows)' in page
