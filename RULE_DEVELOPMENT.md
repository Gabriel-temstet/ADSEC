# Developpement d'une regle de detection

Ce document complete `PLUGIN_DEVELOPMENT.md` (contrat `CheckPlugin`) en
decrivant les conventions suivies par les regles existantes d'ADSEC, pour
que toute nouvelle regle s'integre naturellement au reste du produit.

## Utiliser `rules/factory.py`

Toute regle doit construire ses findings via `new_finding()`
(`adsec/rules/factory.py`) plutot que d'instancier `Finding` directement.
La factory impose la structure `technical_details` = "Pourquoi detecte /
Pourquoi risque / Faux positif possible", qui est la structure attendue
par le reste du produit (rapports, `adsec findings show`) :

```python
from adsec.rules.factory import new_finding

finding = new_finding(
    rule_id=self.id,
    category=self.category,
    title="...",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="...",
    why_detected="Fait technique observe, verifiable independamment.",
    why_risky="Pourquoi ce fait est une vraie faiblesse de securite.",
    false_positive="Ce qui pourrait rendre ce signal non pertinent.",
    impact="...",
    validation="Comment le pentester verifie manuellement, sans exploiter.",
    remediation="...",
    assets=[...],
    principal=sid_ou_dn,
    condition_key="identifiant-court-de-la-condition",
    evidence=[...],
    references=[...],
)
```

## `principal` et `condition_key` : deduplication ET correlation

Ces deux champs ne sont pas de simples metadonnees :

- Ils alimentent `Finding.fingerprint()` (deduplication entre scans — voir
  `database/repositories/findings.py`).
- `principal` est aussi utilise par `graph/correlation.py` pour relier un
  finding aux chemins d'attaque qui en decoulent. S'il s'agit d'un SID
  connu dans l'annuaire, utilisez le SID (pas le DN) : la correlation
  resout elle-meme SID -> DN via `graph.builder.build_sid_to_dn`.

Si une nouvelle regle ACL/GPO introduit une relation deja presente dans
`graph/builder.py` (ex: un nouveau droit qui equivaut a `CAN_WRITE`),
ajoutez son `rule_id` a `_RULE_TO_RELATION` dans
`graph/correlation.py` pour que la correlation fonctionne.

## Enregistrer le profil de risque

Chaque `rule_id` doit avoir une entree dans `RISK_PROFILES`
(`adsec/rules/risk.py`) : un couple `(ImpactLevel, ExploitabilityLevel)`
attribue a la conception de la regle, jamais calcule dynamiquement. Sans
entree, le profil par defaut (`LOCAL`, `REQUIRES_ACCESS`) s'applique — ce
qui sous-estime generalement l'impact reel, donc ajoutez toujours
l'entree explicitement :

```python
"AD-XXX-NNN": (ImpactLevel.LATERAL, ExploitabilityLevel.REQUIRES_ACCESS),
```

Voir les commentaires en tete de `rules/risk.py` pour la signification de
chaque niveau.

## Mapping MITRE ATT&CK

Renseignez `mitre_technique_id` uniquement si une technique correspond de
facon fiable et specifique (pas une technique generique "Valid Accounts"
pour tout). Laissez `None` plutot que de forcer un mapping approximatif —
plusieurs regles ACL/GPO d'ADSEC n'ont volontairement aucun mapping pour
cette raison.

## Tester une regle

1. Ajoutez le scenario necessaire a `tests/fixtures/corp_example.py` (ou
   un autre fixture dedie si le scenario ne concerne pas LDAP/ACL — voir
   `tests/fixtures/fake_smb.py` et `fake_dns.py` pour SMB/DNS).
2. Ecrivez un test unitaire appelant directement `plugin.run(ctx, data)`
   avec une `NormalizedData` construite a la main (voir
   `tests/unit/test_acl_trust_rules.py`, `test_kerberos_gpo_rules.py`,
   `test_smb_dns_rules.py` pour des exemples).
3. Si la regle doit se correler a un chemin d'attaque, ajoutez un
   scenario dans `tests/unit/test_correlation_risk.py`.
4. Verifiez `mypy adsec/`, `ruff check adsec/`, `bandit -r adsec/` et
   `pytest` avant de livrer.
