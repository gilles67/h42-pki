"""Built-in certificate profiles: synchronised from the code, read-only (ADR-0009)."""

from typing import Any

from h42pki.core.profiles import BUILTIN_PROFILES, ProfileSpec
from h42pki.models import AuditLog, Profile

SYSTEM_ACTOR = "system"


def _columns(spec: ProfileSpec) -> dict[str, Any]:
    values = {field: getattr(spec, field) for field in ProfileSpec.model_fields if field != "name"}
    values["extended_key_usage"] = list(spec.extended_key_usage)
    values["allowed_key_algorithms"] = [
        algorithm.value for algorithm in spec.allowed_key_algorithms
    ]
    return values


def spec_of(profile: Profile) -> ProfileSpec:
    return ProfileSpec.model_validate(profile.spec_values())


class ProfileService:
    async def sync_builtin(self) -> None:
        """Create missing built-in profiles and realign changed ones on the code (no migration)."""
        for spec in BUILTIN_PROFILES.values():
            profile = await Profile.get_or_none(name=spec.name)
            if profile is None:
                profile = await Profile.create(name=spec.name, builtin=True, **_columns(spec))
                await self._audit("profile.create", profile, {})
                continue
            if profile.builtin and spec_of(profile) == spec:
                continue
            stored = spec_of(profile).model_dump(mode="json")
            expected = spec.model_dump(mode="json")
            changed = sorted(field for field in expected if stored.get(field) != expected[field])
            await profile.update_from_dict({"builtin": True, **_columns(spec)})
            await profile.save()
            await self._audit("profile.realign", profile, {"changed_fields": changed})

    async def list(self) -> list[Profile]:
        return await Profile.all()

    async def get(self, name: str) -> Profile:
        return await Profile.get(name=name)

    @staticmethod
    async def _audit(action: str, profile: Profile, details: dict[str, Any]) -> None:
        await AuditLog.record(
            actor=SYSTEM_ACTOR,
            action=action,
            object_type="profile",
            object_id=profile.id,
            details={"name": profile.name, **details},
        )
