"""A task run at start-up, then at a fixed interval, until the launcher stops.

Failures are logged (business error detail or exception type, never a secret) and kept in
``state`` for ``GET /health``; the next run happens at the next interval.
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from h42pki.errors import H42Error

log = logging.getLogger(__name__)


@dataclass
class TaskState:
    last_run: datetime | None = None
    failing: bool = False
    last_error: str | None = None


class PeriodicTask:
    def __init__(
        self,
        name: str,
        action: Callable[[], Awaitable[object]],
        *,
        interval: float,
        first_delay: float = 0.0,
    ) -> None:
        self.name = name
        self._action = action
        self.interval = interval
        self._first_delay = first_delay
        self.state = TaskState()

    async def run_once(self) -> bool:
        """One run; True when it succeeded."""
        self.state.last_run = datetime.now(UTC)
        try:
            await self._action()
        except Exception as exc:
            reason = exc.detail if isinstance(exc, H42Error) else type(exc).__name__
            self.state.failing = True
            self.state.last_error = reason
            log.warning(
                "scheduled task %s failed (%s); next run in %d s",
                self.name,
                reason,
                round(self.interval),
            )
            log.debug("scheduled task %s failure", self.name, exc_info=True)
            return False
        self.state.failing = False
        self.state.last_error = None
        return True

    async def run(self, stop: asyncio.Event) -> None:
        """Run after ``first_delay``, then every ``interval`` seconds, until ``stop`` is set."""
        delay = self._first_delay
        while True:
            try:
                await asyncio.wait_for(stop.wait(), timeout=delay)
            except TimeoutError:
                pass
            else:
                return
            await self.run_once()
            delay = self.interval
