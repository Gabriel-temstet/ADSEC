"""Collector SMB : negociation (dialecte, signing), session anonyme/invite,
enumeration des partages et test d'accessibilite anonyme par partage.

Aucune lecture ni ecriture de fichier : `can_read_share_anonymously` se
limite a une tentative de connexion d'arborescence (`connectTree`), qui est
l'equivalent SMB d'un bind LDAP anonyme - une verification d'acces, pas une
exploitation.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import ClassVar

from adsec.collectors.base import CollectionResult, DiscoveryResult
from adsec.collectors.smb.session import (
    SMB1_DIALECT_MARKER,
    SmbConnectionError,
    SmbSession,
    build_smb_session,
)
from adsec.core.models.enums import AccessLevel
from adsec.core.scope.scope_manager import ScopeManager
from adsec.credentials.provider import CredentialProvider

# Partages caches par defaut sur tout hote Windows : leur presence seule
# n'est pas une observation utile, seule leur accessibilite anonyme l'est
# (verifiee comme les autres partages, mais on ne les compte pas comme des
# "partages metier" exposes).
_DEFAULT_HIDDEN_SHARES = frozenset({"IPC$", "ADMIN$"})

SessionFactory = Callable[..., SmbSession]


class SmbCollector:
    id = "smb"
    required_access_level: ClassVar[AccessLevel] = AccessLevel.ANONYMOUS
    protocols: ClassVar[list[str]] = ["smb"]

    def __init__(
        self,
        scope_manager: ScopeManager,
        credential_provider: CredentialProvider,
        port: int = 445,
        session_factory: SessionFactory | None = None,
    ) -> None:
        self._scope = scope_manager
        self._credentials = credential_provider
        self._port = port
        self._session_factory = session_factory or build_smb_session

    async def discover(self, target: str) -> DiscoveryResult:
        self._scope.assert_in_scope(target)
        return await asyncio.to_thread(self._discover_sync, target)

    async def collect(self, target: str) -> CollectionResult:
        self._scope.assert_in_scope(target)
        return await asyncio.to_thread(self._collect_sync, target)

    def _open(self, target: str) -> SmbSession:
        credential = self._credentials.get("smb")
        return self._session_factory(target, credential, self._port)

    def _discover_sync(self, target: str) -> DiscoveryResult:
        try:
            session = self._open(target)
        except SmbConnectionError as exc:
            return DiscoveryResult(
                access_level_achieved=AccessLevel.ANONYMOUS,
                partial=True,
                limitations=[str(exc)],
            )
        try:
            dialect = session.dialect()
            access_level = (
                AccessLevel.ANONYMOUS
                if session.is_guest_or_anonymous()
                else AccessLevel.AUTHENTICATED
            )
            return DiscoveryResult(
                access_level_achieved=access_level,
                facts={
                    "dialect": dialect,
                    "is_smb1": dialect == SMB1_DIALECT_MARKER,
                    "signing_required": session.signing_required(),
                    "guest_or_anonymous": session.is_guest_or_anonymous(),
                },
            )
        finally:
            session.close()

    def _collect_sync(self, target: str) -> CollectionResult:
        try:
            session = self._open(target)
        except SmbConnectionError as exc:
            return CollectionResult(objects={"shares": []}, partial=True, errors=[str(exc)])

        shares: list[dict[str, object]] = []
        errors: list[str] = []
        limitations: list[str] = []
        try:
            try:
                share_list = session.list_shares()
            except Exception as exc:  # noqa: BLE001 - enumeration refusee = limite, pas un crash
                errors.append(f"Enumeration des partages refusee sur {target!r}: {exc}")
                share_list = []

            for share in share_list:
                anonymous_readable = False
                if share.name.upper() not in _DEFAULT_HIDDEN_SHARES:
                    try:
                        anonymous_readable = session.can_read_share_anonymously(share.name)
                    except Exception:  # noqa: BLE001 - test d'acces best-effort
                        anonymous_readable = False
                shares.append(
                    {
                        "name": share.name,
                        "remark": share.remark,
                        "is_hidden_admin_share": share.is_hidden_admin_share,
                        "anonymous_readable": anonymous_readable,
                    }
                )
        finally:
            session.close()

        return CollectionResult(
            objects={"shares": shares},
            partial=bool(limitations),
            limitations=limitations,
            errors=errors,
        )
