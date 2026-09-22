import sys

from ioc_rejudge.cli import main


if len(sys.argv) > 1 and sys.argv[1] in {
    "roadmap",
    "job",
    "review",
    "explain",
    "health",
    "history",
    "cache",
    "import-table",
    "export-bundle",
}:
    from ioc_rejudge.roadmap_cli import main as roadmap_main

    roadmap_argv = sys.argv[2:] if sys.argv[1] == "roadmap" else sys.argv[1:]
    raise SystemExit(roadmap_main(roadmap_argv))

if len(sys.argv) > 1 and sys.argv[1] == "share":
    from ioc_rejudge.share import main as share_main

    raise SystemExit(share_main(sys.argv[2:]))

if len(sys.argv) > 1 and sys.argv[1] == "ui":
    from ioc_rejudge.ui import main as ui_main

    raise SystemExit(ui_main(sys.argv[2:]))

main()
