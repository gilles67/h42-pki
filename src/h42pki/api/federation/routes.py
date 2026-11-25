"""Federation routes, parent side (docs/protocols/federation.md).

Invitations and child CAs have no authentication until the first release (ADR-0008); ``enroll`` is
authenticated by the invitation token. Responses are never cached.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Response, status

from h42pki.api.admin.deps import Actor, app_settings, keystore
from h42pki.api.federation.schemas import (
    ChildOut,
    ChildRevoke,
    EnrollOut,
    EnrollRequest,
    InvitationCreate,
    InvitationCreated,
    InvitationOut,
)
from h42pki.api.problems import PROBLEM_RESPONSES, UNAUTHORIZED_RESPONSE
from h42pki.config import Settings
from h42pki.keystore import KeyStore
from h42pki.services.federation import FederationService

# Suggested polling interval of a pending enrolment.
RETRY_AFTER_SECONDS = 10

STATUS_CODES = {
    "issued": status.HTTP_201_CREATED,
    "pending": status.HTTP_202_ACCEPTED,
}


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


router = APIRouter(
    prefix="/api/v1/federation",
    tags=["federation"],
    responses=PROBLEM_RESPONSES,
    dependencies=[Depends(_no_store)],
)


def federation_service(store: Annotated[KeyStore, Depends(keystore)]) -> FederationService:
    return FederationService(store)


def bearer_token(
    authorization: Annotated[str | None, Header(include_in_schema=False)] = None,
) -> str | None:
    scheme, _, value = (authorization or "").partition(" ")
    return value.strip() if scheme.lower() == "bearer" else None


Federation = Annotated[FederationService, Depends(federation_service)]
Token = Annotated[str | None, Depends(bearer_token)]


@router.post("/invitations", status_code=status.HTTP_201_CREATED)
async def create_invitation(
    body: InvitationCreate,
    actor: Actor,
    federation: Federation,
    settings: Annotated[Settings, Depends(app_settings)],
) -> InvitationCreated:
    created = await federation.invite(**body.model_dump(), actor=actor)
    return InvitationCreated.from_created(created, parent_url=settings.https_url)


@router.get("/invitations")
async def list_invitations(federation: Federation) -> list[InvitationOut]:
    return [InvitationOut.from_model(invitation) for invitation in await federation.list()]


@router.get("/invitations/{invitation_id}")
async def get_invitation(invitation_id: UUID, federation: Federation) -> InvitationOut:
    return InvitationOut.from_model(await federation.get(invitation_id))


@router.delete("/invitations/{invitation_id}")
async def revoke_invitation(
    invitation_id: UUID, actor: Actor, federation: Federation
) -> InvitationOut:
    return InvitationOut.from_model(await federation.revoke_invitation(invitation_id, actor=actor))


def _enroll_out(out: EnrollOut, response: Response) -> EnrollOut:
    if out.status == "pending":
        response.headers["Retry-After"] = str(RETRY_AFTER_SECONDS)
    return out


@router.post(
    "/enroll",
    status_code=status.HTTP_201_CREATED,
    responses={
        202: {"model": EnrollOut, "description": "Waiting for a manual decision"},
        **UNAUTHORIZED_RESPONSE,
    },
)
async def enroll(
    body: EnrollRequest, token: Token, federation: Federation, response: Response
) -> EnrollOut:
    out = EnrollOut.from_enrolment(
        await federation.enroll(
            token, csr=body.csr_pem, name=body.name, public_base_url=body.public_base_url
        )
    )
    response.status_code = STATUS_CODES.get(out.status, status.HTTP_200_OK)
    return _enroll_out(out, response)


@router.get("/enroll/{enrollment_id}", responses=UNAUTHORIZED_RESPONSE)
async def enrollment_status(
    enrollment_id: UUID, token: Token, federation: Federation, response: Response
) -> EnrollOut:
    out = EnrollOut.from_enrolment(await federation.enrolment(token, enrollment_id))
    return _enroll_out(out, response)


@router.get("/children")
async def list_children(federation: Federation) -> list[ChildOut]:
    return [ChildOut.from_model(child) for child in await federation.children()]


@router.post("/children/{name}/revoke")
async def revoke_child(
    name: str, body: ChildRevoke, actor: Actor, federation: Federation
) -> ChildOut:
    return ChildOut.from_model(await federation.revoke_child(name, reason=body.reason, actor=actor))
