from ioc_rejudge.review_queue import append_label, build_queue, load_queue, summarize

def test_build_filter_sort_and_summary(tmp_path):
    rows=build_queue([{"ioc":"z.invalid","disposition":"review","conclusion":"待复核"},{"ioc":"a.invalid","disposition":"black"}])
    assert [r["ioc"] for r in rows]==["z.invalid"]
    assert summarize(rows)["unreviewed"]==1
    append_label(tmp_path/"q.jsonl", "z.invalid", label="恶意", reviewer="A", reviewed_at="2026-01-01T00:00:00Z")
    loaded=load_queue(tmp_path/"q.jsonl")
    assert loaded[0]["label"]=="恶意" and summarize(loaded)["reviewed"]==1

def test_load_skips_bad_lines(tmp_path):
    p=tmp_path/"q"; p.write_text("bad\n{\"ioc\":\"x.invalid\"}\n", encoding="utf-8")
    assert load_queue(p)[0]["ioc"]=="x.invalid"
