# Developpement d'un CheckPlugin

## Contrat minimal

```python
from adsec.core.models.enums import AccessLevel, Confidence, Severity
from adsec.rules.base import CheckPlugin, DataRequirement, Finding, NormalizedData, ScanContext


class MyCheck(CheckPlugin):
    id = "AD-XXX-NNN"              # unique dans tout le produit
    name = "Nom lisible du controle"
    version = "1.0.0"
    category = "ldap"              # ldap | kerberos | acl | gpo | smb | dns | security | ...
    description = "Ce que verifie ce controle."
    severity_hint = Severity.HIGH
    required_permissions = AccessLevel.AUTHENTICATED
    protocols = ["ldap"]
    intrusive = False              # True => exclu par defaut du moteur

    def requires(self) -> list[DataRequirement]:
        return [DataRequirement(kind="users", description="Liste des comptes utilisateurs")]

    async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
        findings = []
        for user in data.get("users"):
            if <condition dangereuse>:
                findings.append(Finding(
                    rule_id=self.id,
                    title="...",
                    category=self.category,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description="...",
                    technical_details="...",
                    impact="...",
                    validation_procedure="...",
                    remediation="...",
                    affected_assets=[user["dn"]],
                ))
        return findings
```

## Regles imperatives

- **Aucune modification de l'environnement audite.** Un controle observe et
  documente, il n'exploite jamais automatiquement.
- **`intrusive = True`** uniquement si le plugin effectuerait une action non
  passive (meme en lecture ambigue). Ces plugins sont exclus par defaut par
  le `PluginManager` et necessitent `allow_intrusive=True` explicite.
- **Toutes les metadonnees de classe sont obligatoires** (`id`, `name`,
  `version`, `category`, `description`, `severity_hint`,
  `required_permissions`, `protocols`) : `CheckPlugin.__init_subclass__`
  leve `TypeError` a la definition de la classe si l'une d'elles manque.
- **`id` unique** : le `PluginManager` leve `DuplicatePluginIdError` si deux
  plugins declarent le meme `id` avec des classes differentes.
- **Confidence honnete** : `Confidence.LOW` si le controle peut produire des
  faux positifs credibles, `HIGH` uniquement si la preuve est directe et non
  ambigue.
- **`Finding.fingerprint()`** sert a la deduplication entre plugins : deux
  controles differents detectant le meme probleme sur le meme objet avec le
  meme principal doivent produire la meme empreinte (meme `rule_id` +
  memes `affected_assets` + meme `principal`/`condition_key`).

## Decouverte

Un plugin place sous `adsec/rules/<categorie>/` est decouvert
automatiquement par `PluginManager.discover()` (aucune inscription
manuelle necessaire). Les plugins tiers peuvent aussi etre exposes via un
entry point `adsec.plugins` dans leur `pyproject.toml` :

```toml
[project.entry-points."adsec.plugins"]
my_check = "my_package.checks:MyCheck"
```

## Tester un plugin

Voir `tests/unit/test_plugin_manager.py` pour des exemples complets
(plugin normal, plugin intrusif, filtrage par niveau d'acces, calcul de
fingerprint).
