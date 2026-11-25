"""Helpers for tests that read the output of the CLI."""

from subprocess import CompletedProcess
from typing import Literal

import click
from click.testing import Result


def plain(
    result: Result | CompletedProcess[str],
    stream: Literal["output", "stdout", "stderr"] = "output",
) -> str:
    """CLI output without ANSI styling.

    Typer forces colours on GitHub Actions, and Rich may split a word such as ``--validity-days``
    with style codes: never compare raw output. ``output`` (stdout and stderr interleaved) only
    exists on ``CliRunner`` results.
    """
    return click.unstyle(getattr(result, stream))
