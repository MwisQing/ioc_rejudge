"""Compatibility entry point for the migrated IOC Info provider."""

from ioc_rejudge.providers.ioc_info import *  # noqa: F401,F403


if __name__ == "__main__":
    raise SystemExit(main())
