# Reporting

## Formats disponibles

```bash
adsec report generate <engagement> --kind technical --format markdown
adsec report generate <engagement> --kind executive --format html
adsec report generate <engagement> --format json      # pas de --kind : export brut
adsec report generate <engagement> --format csv        # idem
```

- `--kind executive` : resume pour un public non technique (statistiques,
  constats critiques/eleves uniquement, chemins d'attaque principaux,
  limitations). Pas de preuves brutes ni de details techniques.
- `--kind technical` : rapport complet (methodologie, tous les findings
  avec preuves et procedure de validation, tous les chemins d'attaque).
- `--format json` / `--format csv` : export brut de tous les findings
  (ignorent `--kind`), destine a une consommation programmatique ou a un
  tableur. Le JSON est suffisamment structure pour alimenter une
  plateforme externe (voir le schema dans `export/json_export.py`).
- `--output <chemin>` : surcharge l'emplacement par defaut
  (`<data_dir>/reports/<engagement_id>/...`).

## Sanitisation

```bash
adsec report generate <engagement> --kind technical --format html --sanitize
```

`--sanitize` masque dans le texte genere : adresses IPv4, adresses email,
et tout motif ressemblant a un secret (password/token/ticket/hash/secret,
reprise de `core/events/audit_log.redact`). Les identifiants AD (SID, DN,
noms de compte) restent visibles : ce ne sont pas des secrets et sont
necessaires a la comprehension du finding. `--sanitize` n'affecte que les
rapports narratifs (markdown/html) ; les exports `json`/`csv` sont toujours
bruts puisqu'ils sont destines a un usage interne.

## Baseline et diff

Pour suivre l'evolution d'un environnement entre deux audits :

```bash
adsec scan run ACME-2026-001 dc01.acme.local --profile deep
adsec baseline create ACME-2026-001 --label "Audit initial"

# ... quelques mois plus tard, apres un nouveau scan ...
adsec scan run ACME-2026-001 dc01.acme.local --profile deep
adsec diff ACME-2026-001
```

`adsec diff` compare l'etat courant (findings + compteurs d'objets) a la
baseline la plus recente (ou `--baseline <id>` pour en choisir une autre)
et affiche :

- les findings NOUVEAUX (fingerprint absent de la baseline) ;
- les findings RESOLUS (fingerprint present dans la baseline, absent
  aujourd'hui) ;
- les deltas de compteurs d'objets (utilisateurs, groupes, ordinateurs,
  findings, chemins d'attaque).

**Limitation connue** : ce diff compare l'etat courant a un instantane
(`baseline`), pas deux scans historiques arbitraires l'un a l'autre — les
findings sont mis a jour en place a chaque scan (voir
`database/repositories/findings.py`), il n'existe pas aujourd'hui
d'historique complet multi-scans interrogeable. Pour comparer deux audits
precis, creez une baseline juste apres chacun d'eux.

## Evidence et export BloodHound

- Chaque finding est accompagne de preuves hashees (SHA-256), consultables
  via `adsec findings show <engagement> <finding_id>`.
- `adsec export bloodhound <engagement>` ecrit 6 fichiers JSON
  (`users.json`, `groups.json`, `computers.json`, `domains.json`,
  `gpos.json`, `relationships.json`) dans un format compatible avec les
  outils publics utilises par BloodHound. Voir `ARCHITECTURE.md` pour les
  limites de cet export (sous-ensemble raisonnable, pas une fidelite
  complete au schema BloodHound).
