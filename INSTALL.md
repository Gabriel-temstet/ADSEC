# Installation

## Prerequis

- Python 3.11 ou 3.12
- pip

## Installation en environnement virtuel (recommande)

```bash
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate         # Windows

pip install -e ".[dev]"
```

## Verification de l'installation

```bash
adsec doctor run
```

Cette commande verifie :

- la version de Python ;
- le chargement de la configuration (`~/.adsec` par defaut, surchargeable
  via `ADSEC_DATA_DIR`) ;
- les profils de scan disponibles ;
- les parametres de securite operationnelle par defaut ;
- la creation/migration de la base SQLite ;
- la decouverte des plugins de controle.

Toute ligne `ECHEC` doit etre resolue avant utilisation en mission.

## Configuration

Toutes les variables d'environnement sont prefixees `ADSEC_` :

| Variable            | Role                                  | Defaut       |
|---------------------|----------------------------------------|--------------|
| `ADSEC_DATA_DIR`    | Repertoire de donnees (DB, audit, rapports) | `~/.adsec` |
| `ADSEC_LOG_LEVEL`   | Niveau de log (DEBUG/INFO/WARNING/ERROR) | `INFO`     |
| `ADSEC_LOG_FORMAT`  | `json` ou `console`                    | `json`       |
| `ADSEC_DEFAULT_OPERATOR` | Nom d'operateur par defaut pour les engagements | (aucun) |

## Via Docker

```bash
docker build -t adsec .
docker run --rm -v adsec-data:/data adsec doctor run
docker run --rm -v adsec-data:/data adsec client create ACME
```

Les donnees (base SQLite, rapports, audit log) sont persistees dans le
volume monte sur `/data` (`ADSEC_DATA_DIR`). Le conteneur tourne en
utilisateur non-root.

> Le `Dockerfile` n'a pas pu etre valide par une construction reelle dans
> l'environnement de developpement (aucun demon Docker disponible) :
> testez-le avant un usage en production.

## Desinstallation

```bash
pip uninstall adsec
rm -rf ~/.adsec   # supprime aussi toutes les donnees de mission locales
```
