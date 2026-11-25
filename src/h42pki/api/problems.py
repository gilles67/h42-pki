"""Exception handlers rendering errors as ``application/problem+json`` (RFC 9457)."""

from collections.abc import Callable, Coroutine, Mapping
from http import HTTPStatus
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response
from tortoise.exceptions import DoesNotExist, IntegrityError, ValidationError

from h42pki.errors import H42Error

PROBLEM_JSON = "application/problem+json"
PROBLEM_SCHEMA_REF = "#/components/schemas/Problem"


class ProblemFieldError(BaseModel):
    """One request validation error (never the submitted value, which may be a secret)."""

    loc: list[str | int]
    msg: str
    type: str


class Problem(BaseModel):
    """Problem details (RFC 9457) returned by every error of the API."""

    type: str = "about:blank"
    title: str
    status: int
    detail: str
    instance: str | None = None
    errors: list[ProblemFieldError] | None = Field(
        default=None, description="Request validation errors (422 only)."
    )


def _problem_response(description: str) -> dict[str, Any]:
    return {
        "description": description,
        "content": {PROBLEM_JSON: {"schema": {"$ref": PROBLEM_SCHEMA_REF}}},
    }


# Declared on the routers. FastAPI then no longer adds its own 422 response (and its
# HTTPValidationError / ValidationError schemas): it only does so when an operation has no
# 422, 4XX or default response (fastapi/openapi/utils.py, FastAPI 0.136).
PROBLEM_RESPONSES: dict[int | str, dict[str, Any]] = {
    404: _problem_response("Not Found"),
    409: _problem_response("Conflict"),
    422: _problem_response("Unprocessable Content (invalid request or refused by a rule)"),
    503: _problem_response("Service Unavailable (no active certificate authority)"),
}


def install_problem_schemas(app: FastAPI) -> None:
    """Add the Problem schemas to the OpenAPI components referenced by PROBLEM_RESPONSES."""

    def openapi() -> dict[str, Any]:
        if app.openapi_schema is None:
            schema = get_openapi(
                title=app.title, version=app.version, routes=app.routes, tags=app.openapi_tags
            )
            problem = Problem.model_json_schema(ref_template="#/components/schemas/{model}")
            components = schema.setdefault("components", {}).setdefault("schemas", {})
            components.update(problem.pop("$defs", {}))
            components["Problem"] = problem
            app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = openapi  # type: ignore[method-assign]


ExceptionHandler = Callable[[Request, Any], Coroutine[Any, Any, Response]]


def problem(
    status: int,
    title: str,
    detail: str,
    *,
    headers: Mapping[str, str] | None = None,
    **extensions: Any,
) -> JSONResponse:
    """Build a problem details response; ``extensions`` become extra members (RFC 9457 3.2)."""
    return JSONResponse(
        status_code=status,
        headers=headers,
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


# Read-only resources whose writes go through the CLI until the API has authentication.
READ_ONLY_HINTS = {
    "/api/v1/config": "settings are changed with `h42pki config set|unset` (ADR-0011)",
    "/api/v1/profiles": "built-in profiles are read-only (ADR-0009)",
}


def _method_not_allowed_detail(request: Request) -> str:
    detail = f"method {request.method} is not allowed on this resource"
    for prefix, hint in READ_ONLY_HINTS.items():
        if request.url.path == prefix or request.url.path.startswith(f"{prefix}/"):
            return f"{detail}: {hint}"
    return detail


async def _http_exception(request: Request, exc: StarletteHTTPException) -> Response:
    """Routing errors of Starlette (404 unknown route, 405 wrong method) as problem+json."""
    if exc.status_code == 404:
        detail = "the requested resource does not exist"
    elif exc.status_code == 405:
        detail = _method_not_allowed_detail(request)
    else:
        detail = str(exc.detail)
    return problem(exc.status_code, HTTPStatus(exc.status_code).phrase, detail, headers=exc.headers)


async def _does_not_exist(request: Request, exc: DoesNotExist) -> Response:
    return problem(404, "Not Found", "the requested resource does not exist")


async def _integrity_error(request: Request, exc: IntegrityError) -> Response:
    # The database message may leak schema details: keep it out of the response.
    return problem(409, "Conflict", "the request conflicts with existing data")


async def _model_validation_error(request: Request, exc: ValidationError) -> Response:
    # A value too long for its column, also raised on query filters (B48). No echo of the value.
    return problem(422, "Unprocessable Content", "a value is not valid for its field")


def exception_handlers() -> dict[int | type[Exception], ExceptionHandler]:
    """Handlers to pass to ``FastAPI(exception_handlers=...)``."""
    return {
        H42Error: _h42_error,
        StarletteHTTPException: _http_exception,
        RequestValidationError: _request_validation_error,
        DoesNotExist: _does_not_exist,
        IntegrityError: _integrity_error,
        ValidationError: _model_validation_error,
    }
