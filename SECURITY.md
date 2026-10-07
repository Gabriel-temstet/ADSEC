# Modele de securite

## Posture par defaut

ADSEC est **SAFE / NON-DESTRUCTIF par defaut**. Aucune commande livree en
Phase 2 ne modifie l'environnement audite. Cette garantie s'etend aux
phases suivantes via deux mecanismes structurels :

1. **`ScopeManager.assert_in_scope()`** doit etre appele par tout futur
   collector avant la moindre operation reseau. Une cible hors scope leve
   `OutOfScopeError` et bloque l'operation.
2. **`CheckPlugin.intrusive`** : un plugin marque `intrusive=True` est
   exclu par defaut par `PluginManager.select_plugins()`. Son activation
   necessite `allow_intrusive=True` explicite **et** que le scope de
   l'engagement autorise les actions intrusives
   (`Scope.intrusive_actions_enabled=True`, verifie par
   `ScopeManager.assert_intrusive_allowed()`).

## Credentials

Aucun secret n'est jamais stocke en clair. `CredentialsMetadata.secret_ref`
est une reference opaque resolue par un `CredentialProvider` au moment de
l'execution (variable d'environnement, session Kerberos deja etablie,
coffre externe). Une validation refuse toute valeur de `secret_ref`
contenant un motif de secret en clair (`password=`, `secret=`, etc.).

## Masquage des secrets dans les logs

- `adsec.core.events.audit_log.redact()` masque systematiquement les motifs
  `password`, `token`, `ticket`, `hash`, `secret`, `private key` (avec leur
  valeur associee) dans toute entree d'audit log.
- Le formatter JSON de logging (`adsec/logging_setup.py`) applique le meme
  masquage a tous les messages et donnees structurees des logs applicatifs.

## Isolation multi-engagement

Toutes les tables metier (`scopes`, `credentials_metadata`, `scan_jobs`,
`scan_events`, et les tables a venir : `findings`, `evidence`,
`attack_paths`, ...) portent une colonne `engagement_id`. Aucune requete de
repository ne retourne de donnees inter-engagements ; les tests
d'integration (`tests/unit/test_database.py::test_engagement_isolation_between_clients`)
verifient cette isolation.

## Securite operationnelle du scheduler

Le `Scheduler` applique par defaut (`config/defaults/safety.yaml`) :

- `max_workers` : 10
- `max_requests_per_second` : 20
- `max_duration_minutes` : 120
- `stop_on_error_rate` : 0.30 (arret automatique si le taux d'echec depasse
  30% apres un minimum de taches observees)
- `circuit_breaker_failure_threshold` : 5 echecs consecutifs avant
  ecartement temporaire d'une cible

## Kill switch

`Scheduler.request_stop()` declenche un arret cooperatif : les taches en
cours d'execution se terminent, les taches en attente sont marquees
`CANCELLED`, et tous les resultats deja obtenus restent disponibles via
`Scheduler.results`.

## Preuves et rapports

Chaque preuve d'un finding (`evidence`) est hashee (SHA-256) a la
persistance : voir `database/repositories/findings.py::evidence_hash`.
Cela permet de demontrer qu'un finding est bien base sur une donnee
reellement collectee, sans avoir a reproduire la collecte.

Les rapports narratifs (`adsec report generate --format markdown|html`)
acceptent `--sanitize`, qui masque IP/emails/secrets dans le texte genere
(`reporting/sanitizer.py`) — voir `REPORTING.md`. Les exports bruts
(`--format json|csv`) ne sont jamais sanitises : ils sont destines a un
usage interne, pas a une diffusion large.

## Signalement d'une vulnerabilite

Pour signaler une vulnerabilite dans ADSEC lui-meme (et non dans un
environnement audite avec l'outil), contacter l'equipe responsable du
depot avant toute divulgation publique.
