import sys

from ioc_rejudge.cli import main


if len(sys.argv) > 1 and sys.argv[1] == "share":
    from ioc_rejudge.share import main as share_main

    raise SystemExit(share_main(sys.argv[2:]))

main()
