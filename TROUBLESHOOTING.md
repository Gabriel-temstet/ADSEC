# Depannage

## `adsec doctor run` remonte un ECHEC

- **Version Python** : ADSEC requiert Python 3.11+. Verifier avec `python --version`.
- **Base SQLite** : verifier les droits d'ecriture sur `ADSEC_DATA_DIR`
  (par defaut `~/.adsec`). Supprimer `adsec.sqlite3` force une recreation
  complete (perte des donnees locales).
- **Plugins** : une erreur de chargement de plugin apparait dans
  `PluginManager.load_errors`. Verifier qu'aucun module sous
  `adsec/rules/` ou `adsec/plugins/` ne leve d'exception a l'import.

## `EngagementAlreadyExistsError` / `ClientAlreadyExistsError`

Le nom est deja pris (unicite du nom de client globale, unicite du nom
d'engagement par client). Utiliser `adsec client list` / `adsec engagement
list <client>` pour verifier l'existant avant creation.

## `OutOfScopeError` inattendue

Utiliser `adsec scope test <engagement> <cible>` pour comprendre pourquoi
une cible est jugee hors scope. Rappel de la regle de priorite : une
exclusion (`host-exclude` / `network-exclude`) l'emporte toujours sur une
inclusion, meme plus specifique.

## Le scheduler s'arrete avant la fin des taches soumises

Comportement attendu si :

- le kill switch a ete active (`Scheduler.request_stop()`) ;
- la duree maximale (`max_duration_minutes`) est atteinte ;
- le taux d'erreur depasse `stop_on_error_rate` (apres
  `min_tasks_before_error_rate_check` taches observees).

Les resultats deja obtenus restent disponibles via `Scheduler.results`
(statuts `SUCCEEDED`/`FAILED` pour les taches deja traitees, `CANCELLED`
pour les taches restantes).

## `adsec diff` echoue avec "Aucune baseline"

`adsec diff` compare toujours a une baseline explicite (`adsec baseline
create`), jamais a un scan precedent directement. Creez-en une avant le
premier diff ; voir `REPORTING.md`.

## `adsec report generate --format json/csv` echoue avec "Aucun finding"

Ces deux formats exportent les findings deja persistes : lancez `adsec
scan run` avant. `--format markdown/html` fonctionnent meme sans finding
(rapport avec une section "Aucun constat").

## `pip install` produit un paquet qui echoue a l'execution (profils/schema introuvables)

Verifier que `pyproject.toml` contient bien `[tool.setuptools.package-data]`
avec `adsec = ["config/defaults/*.yaml", "database/schema/*.sql"]` — sans
cette declaration, les fichiers de configuration et les migrations ne sont
pas inclus dans le wheel. Reconstruire avec `python -m build` et verifier
le contenu avec `unzip -l dist/*.whl | grep -E "yaml|sql"`.

## L'image Docker ne demarre pas / le build echoue

Le `Dockerfile` fourni n'a pas pu etre valide par une construction reelle
dans l'environnement de developpement (pas de demon Docker disponible).
`impacket` est pur Python et ne necessite aucune dependance systeme pour
s'installer ; `libkrb5-3`/`libkrb5support0` (bibliotheques d'execution,
pas de paquets `-dev`) sont installees dans l'image finale uniquement pour
le support Kerberos au moment de l'authentification SMB contre une cible
reelle. Verifiez que le build multi-stage a bien acces a PyPI pour
installer `build` et les dependances du wheel.

## `mypy`/`ruff`/`bandit` echouent en local mais pas en CI (ou l'inverse)

Verifier que les versions installees correspondent a celles du workflow
(`pyproject.toml` -> `[project.optional-dependencies].dev`). Executer :

```bash
pip install -e ".[dev]"
pip install bandit types-PyYAML
ruff check adsec/
ruff format --check adsec/
mypy adsec/
bandit -r adsec/
pytest tests/ -v
```
