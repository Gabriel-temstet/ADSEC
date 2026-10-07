"""Identification des trustees SID 'bien connus' pour lesquels un droit
eleve est le comportement normal d'Active Directory et ne doit pas etre
remonte comme une faiblesse (ex: SYSTEM, SELF, Domain Admins sur lui-meme).

Un SID qui n'est PAS dans cette liste et qui detient un droit dangereux sur
un objet privilegie reste une observation a signaler : c'est la ou se
trouvent les vrais chemins d'attaque (delegation excessive, mauvaise
configuration, principal compromis)."""

from __future__ import annotations

_UNIVERSAL_SAFE_SIDS = frozenset(
    {
        "S-1-5-18",  # SYSTEM (LocalSystem)
        "S-1-5-10",  # SELF
        "S-1-3-0",  # CREATOR OWNER
        "S-1-5-9",  # ENTERPRISE DOMAIN CONTROLLERS
    }
)

# RID relatifs (derniere sous-autorite) des groupes integres a privileges
# legitimes sur leur propre domaine.
_SAFE_WELL_KNOWN_RIDS = frozenset(
    {
        "512",  # Domain Admins
        "516",  # Domain Controllers
        "518",  # Schema Admins
        "498",  # Enterprise Read-only Domain Controllers
        "519",  # Enterprise Admins
        "544",  # Administrators (BUILTIN)
    }
)

# SIDs a risque explicite : jamais consideres comme "bien connus/surs",
# meme s'ils sont eux-memes des principaux integres.
_EXPLICITLY_RISKY_SIDS = frozenset(
    {
        "S-1-1-0",  # Everyone
        "S-1-5-11",  # Authenticated Users
        "S-1-5-7",  # Anonymous Logon
    }
)


def is_well_known_safe_trustee(sid: str | None) -> bool:
    if sid is None:
        return False
    if sid in _EXPLICITLY_RISKY_SIDS:
        return False
    if sid in _UNIVERSAL_SAFE_SIDS:
        return True
    last_component = sid.rsplit("-", 1)[-1]
    return last_component in _SAFE_WELL_KNOWN_RIDS
