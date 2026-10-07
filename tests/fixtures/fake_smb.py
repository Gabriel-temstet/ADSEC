"""Session SMB factice pour les tests : implemente le protocole `SmbSession`
sans aucun reseau, avec un scenario representatif (SMBv1, signing non
exige, session invite, un partage public accessible anonymement)."""

from __future__ import annotations

from adsec.collectors.smb.session import SMB1_DIALECT_MARKER, ShareInfo
from adsec.credentials.provider import Credential


class FakeSmbSession:
    def __init__(
        self,
        dialect: str = SMB1_DIALECT_MARKER,
        signing_required: bool = False,
        guest: bool = True,
        shares: list[ShareInfo] | None = None,
        anonymous_readable_shares: frozenset[str] = frozenset({"Public", "IPC$"}),
    ) -> None:
        self._dialect = dialect
        self._signing_required = signing_required
        self._guest = guest
        self._shares = shares or [
            ShareInfo("IPC$"),
            ShareInfo("NETLOGON", "Logon server share"),
            ShareInfo("SYSVOL", "Logon server share"),
            ShareInfo("Public", "Partage public"),
            ShareInfo("C$"),
        ]
        self._anonymous_readable_shares = anonymous_readable_shares
        self.closed = False

    def dialect(self) -> str:
        return self._dialect

    def signing_required(self) -> bool:
        return self._signing_required

    def is_guest_or_anonymous(self) -> bool:
        return self._guest

    def list_shares(self) -> list[ShareInfo]:
        return list(self._shares)

    def can_read_share_anonymously(self, share_name: str) -> bool:
        return share_name in self._anonymous_readable_shares

    def close(self) -> None:
        self.closed = True


def build_fake_smb_session(target: str, credential: Credential, port: int) -> FakeSmbSession:
    return FakeSmbSession()


def build_hardened_smb_session(target: str, credential: Credential, port: int) -> FakeSmbSession:
    """Scenario durci : SMB2, signing exige, pas de session invite, aucun partage public."""
    return FakeSmbSession(
        dialect="0x0302",
        signing_required=True,
        guest=False,
        shares=[ShareInfo("IPC$"), ShareInfo("NETLOGON"), ShareInfo("SYSVOL")],
        anonymous_readable_shares=frozenset(),
    )
