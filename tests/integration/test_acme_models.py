"""ACME tables (ADR-0020): uniqueness and cascades."""

from datetime import UTC, datetime, timedelta

import pytest
from tortoise.exceptions import IntegrityError

from h42pki.models import (
    AcmeAccount,
    AcmeAuthorization,
    AcmeChallenge,
    AcmeNonce,
    AcmeOrder,
    ChallengeType,
    IdentifierType,
    OrderStatus,
    Profile,
)

LATER = datetime.now(UTC) + timedelta(days=1)


@pytest.mark.usefixtures("client")  # the lifespan writes the profiles
async def test_order_tree_and_cascade() -> None:
    account = await AcmeAccount.create(jwk={"kty": "OKP"}, jwk_thumbprint="t1")
    order = await AcmeOrder.create(
        account=account,
        profile=await Profile.get(name="tls_server"),
        expires_at=LATER,
        identifiers=[{"type": "dns", "value": "a.test"}],
    )
    authorization = await AcmeAuthorization.create(
        order=order, identifier_type=IdentifierType.DNS, identifier_value="a.test", expires_at=LATER
    )
    await AcmeChallenge.create(authorization=authorization, type=ChallengeType.HTTP_01, token="k1")  # noqa: S106

    assert order.status is OrderStatus.PENDING and authorization.wildcard is False
    await account.delete()
    assert (await AcmeOrder.all().count(), await AcmeChallenge.all().count()) == (0, 0)


@pytest.mark.usefixtures("client")
async def test_unique_values() -> None:
    await AcmeAccount.create(jwk={}, jwk_thumbprint="same")
    await AcmeNonce.create(value="n", expires_at=LATER)

    with pytest.raises(IntegrityError):
        await AcmeAccount.create(jwk={}, jwk_thumbprint="same")
    with pytest.raises(IntegrityError):
        await AcmeNonce.create(value="n", expires_at=LATER)
