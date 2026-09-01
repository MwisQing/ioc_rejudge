import sys

from ioc_rejudge.cli import main


if len(sys.argv) > 1 and sys.argv[1] == "share":
    from ioc_rejudge.share import main as share_main

    raise SystemExit(share_main(sys.argv[2:]))

if len(sys.argv) > 1 and sys.argv[1] == "ui":
    from ioc_rejudge.ui import main as ui_main

    raise SystemExit(ui_main(sys.argv[2:]))

main()
