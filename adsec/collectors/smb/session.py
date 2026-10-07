"""Abstraction d'une session SMB : `SmbSession` est le contrat utilise par
le collector, `ImpacketSmbSession` l'implemente par-dessus la librairie
`impacket`. Cette separation permet aux tests d'injecter une session
factice (aucun serveur SMB reel necessaire), exactement comme
`ConnectionFactory` pour LDAP.

Toutes les operations sont en lecture seule : negociation de dialecte,
enumeration des partages, tentative de connexion (`connectTree`) pour
verifier l'accessibilite - aucune lecture/ecriture de fichier."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from adsec.core.models.enums import CredentialType
from adsec.credentials.provider import Credential

# Dialectes SMB2/3 negocies (impacket renvoie une chaine "NT LM 0.12" pour
# SMB1, ou un entier de dialecte pour SMB2+).
SMB1_DIALECT_MARKER = "NT LM 0.12"


@dataclass(frozen=True)
class ShareInfo:
    name: str
    remark: str = ""

    @property
    def is_hidden_admin_share(self) -> bool:
        return self.name.endswith("$")


class SmbSession(Protocol):
    def dialect(self) -> str: ...

    def signing_required(self) -> bool: ...

    def is_guest_or_anonymous(self) -> bool: ...

    def list_shares(self) -> list[ShareInfo]: ...

    def can_read_share_anonymously(self, share_name: str) -> bool: ...

    def close(self) -> None: ...


class SmbConnectionError(Exception):
    pass


class ImpacketSmbSession:
    """Implementation reelle, par-dessus `impacket.smbconnection.SMBConnection`."""

    def __init__(self, target: str, credential: Credential, port: int = 445) -> None:
        try:
            from impacket.smbconnection import SMBConnection
        except ImportError as exc:  # pragma: no cover - impacket est une dependance obligatoire
            raise SmbConnectionError("La dependance 'impacket' n'est pas installee") from exc

        try:
            self._conn = SMBConnection(target, target, sess_port=port, timeout=10)
            if credential.credential_type == CredentialType.USER and credential.principal:
                user = credential.principal.split("\\")[-1].split("@")[0]
                self._conn.login(user, credential.secret or "")
            else:
                self._conn.login("", "")  # session anonyme/nulle
        except Exception as exc:
            raise SmbConnectionError(f"Connexion SMB refusee sur {target!r}: {exc}") from exc

    def dialect(self) -> str:
        return str(self._conn.getDialect())

    def signing_required(self) -> bool:
        return bool(self._conn.isSigningRequired())

    def is_guest_or_anonymous(self) -> bool:
        return bool(self._conn.isGuestSession())

    def list_shares(self) -> list[ShareInfo]:
        shares = []
        for share in self._conn.listShares():
            name = (
                share["shi1_netname"][:-1]
                if isinstance(share["shi1_netname"], str)
                else str(share["shi1_netname"])
            )
            remark = share.get("shi1_remark", "")
            shares.append(
                ShareInfo(name=str(name).rstrip("\x00"), remark=str(remark).rstrip("\x00"))
            )
        return shares

    def can_read_share_anonymously(self, share_name: str) -> bool:
        try:
            tree_id = self._conn.connectTree(share_name)
        except Exception:  # noqa: BLE001 - acces refuse = simple resultat negatif, pas une erreur
            return False
        try:
            self._conn.disconnectTree(tree_id)
        except Exception:  # nosec B110 - deconnexion best-effort  # noqa: BLE001, S110
            pass
        return True

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:  # nosec B110 - fermeture best-effort  # noqa: BLE001, S110
            pass


def build_smb_session(target: str, credential: Credential, port: int = 445) -> SmbSession:
    return ImpacketSmbSession(target, credential, port)
