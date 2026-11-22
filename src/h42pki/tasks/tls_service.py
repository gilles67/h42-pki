"""Daily renewal of the built-in HTTPS server certificate (ADR-0013), first task of ``tasks/``.

Once a day the task asks :class:`TlsServiceManager` whether a new certificate is needed (fewer
than ``tls_service.renew_before_days`` left, names changed, expired) and hands a new certificate
to the launcher, which reloads it hot. On failure it logs a warning, marks the status as failing
(``GET /health``) and tries again the next day. A change of the ``tls_service`` settings triggers
a check at once.
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from h42pki.errors import H42Error
from h42pki.models import Certificate
from h42pki.services.tls_service import EnsureResult, TlsServiceManager

log = logging.getLogger(__name__)

RENEWAL_INTERVAL_SECONDS = 24 * 3600.0


@dataclass
class RenewalState:
    failing: bool = False
    last_check: datetime | None = None
    last_error: str | None = None  # short and secret-free: business error detail or type name


class TlsRenewalTask:
    def __init__(
        self,
        manager: TlsServiceManager,
        on_certificate: Callable[[Certificate], Awaitable[None]],
        *,
        interval: float | None = None,
    ) -> None:
        self._manager = manager
        self._on_certificate = on_certificate
        self._interval = interval
        self._wake = asyncio.Event()
        self.state = RenewalState()

    @property
    def interval(self) -> float:
        return self._interval if self._interval is not None else RENEWAL_INTERVAL_SECONDS

    def check_soon(self) -> None:
        """Run a check now instead of waiting for the next day (settings changed)."""
        self._wake.set()

    async def check(self) -> EnsureResult | None:
        self.state.last_check = datetime.now(UTC)
        try:
            result = await self._manager.ensure()
            if result.issued and result.certificate is not None:
                log.info(
                    "HTTPS server certificate issued (%s): serial %s, valid until %s",
                    result.reason,
                    result.certificate.serial_hex,
                    result.certificate.not_after.isoformat(),
                )
                await self._on_certificate(result.certificate)
        except Exception as exc:
            reason = exc.detail if isinstance(exc, H42Error) else type(exc).__name__
            self.state.failing = True
            self.state.last_error = reason
            log.warning(
                "renewal of the HTTPS server certificate failed (%s); next attempt in %d h",
                reason,
                round(self.interval / 3600),
            )
            return None
        self.state.failing = False
        self.state.last_error = None
        return result

    async def run(self, stop: asyncio.Event) -> None:
        """Check every ``interval`` seconds (or when woken) until ``stop`` is set."""
        while not stop.is_set():
            stop_waiter = asyncio.create_task(stop.wait())
            wake_waiter = asyncio.create_task(self._wake.wait())
            try:
                await asyncio.wait(
                    {stop_waiter, wake_waiter},
                    timeout=self.interval,
                    return_when=asyncio.FIRST_COMPLETED,
                )
            finally:
                stop_waiter.cancel()
                wake_waiter.cancel()
            if stop.is_set():
                return
            self._wake.clear()
            await self.check()
