"""
Frozen entry point.

PyInstaller needs a plain script rather than a package's __main__, and
freeze_support has to run before anything else touches multiprocessing.
"""

import multiprocessing
import sys


def main() -> int:
    multiprocessing.freeze_support()
    from app.main import main as run

    return run()


if __name__ == "__main__":
    sys.exit(main())
