"""Compatibility entry point for the original WebShield script."""

import sys

from webshield.cli import main


if __name__ == "__main__":
    arguments = sys.argv[1:]
    if arguments and arguments[0] != "scan":
        arguments.insert(0, "scan")
    main(arguments)