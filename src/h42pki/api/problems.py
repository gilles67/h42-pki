"""Exception handlers rendering errors as ``application/problem+json`` (RFC 9457)."""

from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.responses import Response
from tortoise.exceptions import DoesNotExist, IntegrityError

from h42pki.errors import H42Error

PROBLEM_JSON = "application/problem+json"

ExceptionHandler = Callable[[Request, Any], Coroutine[Any, Any, Response]]


def problem(status: int, title: str, detail: str, **extensions: Any) -> JSONResponse:
    """Build a problem details response; ``extensions`` become extra members (RFC 9457 3.2)."""
    return JSONResponse(
        status_code=status,
        content={
            "type": "about:blank",
            "title": title,
            "status": status,
            "detail": detail,
            **extensions,
        },
        media_type=PROBLEM_JSON,
    )


async def _h42_error(request: Request, exc: H42Error) -> Response:
    return problem(exc.status_code, exc.title, exc.detail)


async def _request_validation_error(request: Request, exc: RequestValidationError) -> Response:
    # Only loc, msg and type: the submitted value ("input") may be a secret (B29).
    errors = [
        {
            "loc": list(error.get("loc", ())),
            "msg": error.get("msg", ""),
            "type": error.get("type", ""),
        }
        for error in exc.errors()
    ]
    count = len(errors)
    detail = f"the request is invalid ({count} error{'s' if count != 1 else ''})"
    return problem(422, "Unprocessable Content", detail, errors=errors)


async def _does_not_exist(request: Request, exc: DoesNotExist) -> Response:
    return problem(404, "Not Found", "the requested resource does not exist")


async def _integrity_error(request: Request, exc: IntegrityError) -> Response:
    # The database message may leak schema details: keep it out of the response.
    return problem(409, "Conflict", "the request conflicts with existing data")


def exception_handlers() -> dict[int | type[Exception], ExceptionHandler]:
    """Handlers to pass to ``FastAPI(exception_handlers=...)``."""
    return {
        H42Error: _h42_error,
        RequestValidationError: _request_validation_error,
        DoesNotExist: _does_not_exist,
        IntegrityError: _integrity_error,
    }
