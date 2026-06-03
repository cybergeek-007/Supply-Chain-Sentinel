"""Allow ``python -m src.cli`` execution.

This shim imports and invokes the Click CLI group defined in
:mod:`src.cli.main` so that the package can be run directly::

    python -m src.cli [OPTIONS] COMMAND [ARGS]

It is equivalent to invoking the ``sentinel`` console-script entry
point defined in ``pyproject.toml``.
"""

from src.cli.main import cli

if __name__ == "__main__":
    cli()
