import json
import logging
from collections.abc import Iterator

import pytest

from h42pki.logs import SERVER_LOGGERS, JsonFormatter, configure_logging, set_log_level


@pytest.fixture(autouse=True)
def restore_logging() -> Iterator[None]:
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    levels = {name: logging.getLogger(name).level for name in SERVER_LOGGERS}
    yield
    root.handlers[:] = handlers
    root.setLevel(level)
    for name, previous in levels.items():
        logging.getLogger(name).setLevel(previous)


def test_json_formatter() -> None:
    record = logging.LogRecord(
        "h42pki.test", logging.WARNING, __file__, 1, "hello %s", ("x",), None
    )

    entry = json.loads(JsonFormatter().format(record))

    assert entry["level"] == "warning"
    assert entry["logger"] == "h42pki.test"
    assert entry["message"] == "hello x"
    assert entry["timestamp"].endswith("+00:00")


def test_configure_logging_is_idempotent() -> None:
    configure_logging("json", "info")
    configure_logging("text", "debug")

    ours = [h for h in logging.getLogger().handlers if h.get_name() == "h42pki"]
    assert len(ours) == 1
    assert not isinstance(ours[0].formatter, JsonFormatter)
    assert logging.getLogger("h42pki").level == logging.DEBUG


def test_set_log_level() -> None:
    set_log_level("error")

    assert all(logging.getLogger(name).level == logging.ERROR for name in SERVER_LOGGERS)
