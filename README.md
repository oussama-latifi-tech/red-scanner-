# 🔴 The Red Scanner

Scanner de ports TCP **asynchrone** écrit en Python, avec découverte d'hôtes, détection de services par bannière et export des résultats (JSON, CSV, TXT).

> Projet d'apprentissage : il m'a permis de comprendre comment fonctionnent la découverte d'hôtes, le *TCP connect scan* et l'identification de services. Il ne remplace pas des outils professionnels comme [nmap](https://nmap.org) (voir [les différences](#différences-avec-nmap)).

## ⚠️ Usage éthique et légal

N'utilisez cet outil **que sur des systèmes qui vous appartiennent ou pour lesquels vous avez une autorisation écrite**. Scanner des machines sans permission peut être illégal. Par sécurité, l'outil demande une confirmation avant de scanner une cible non privée (option `--i-have-permission` pour la passer dans un script).

## Fonctionnalités

- **Scan TCP connect** avec le module `socket` (sockets non bloquants) piloté par `asyncio`, avec concurrence et timeout réglables
- **Découverte d'hôtes** : ICMP (commande `ping` du système) puis sondes TCP ; une connexion *refusée* compte aussi comme preuve que l'hôte est actif
- **Détection de services** : port + analyse de la bannière (signatures dans `redscanner/data/signatures.json`), avec envoi de sondes uniquement sur les ports concernés
- **Cibles flexibles** : IP, nom d'hôte, réseau CIDR, ou fichier de cibles
- **Ports flexibles** : `22,80,443`, `1-1024`, ou presets `common` (100 ports courants), `well-known` (1-1024), `all`
- **Export** JSON, CSV (protégé contre l'injection de formules) et TXT
- **Fiabilité** : les erreurs système (ex. trop de fichiers ouverts) ne sont jamais confondues avec un port fermé ; elles sont comptées et signalées
- Affichage en couleurs dans le terminal (désactivé automatiquement si la sortie est redirigée ou si `NO_COLOR` est défini)

## Installation

Python 3.10 ou plus récent.

```bash
git clone https://github.com/oussama-latifi-tech/red-scanner-.git
cd red-scanner
pip install .
```

Ou directement depuis GitHub :

```bash
pip install git+https://github.com/oussama-latifi-tech/red-scanner-.git
```

Vérification :

```bash
redscanner --version
```

## Utilisation

```bash
# Scan des 100 ports courants de ma machine
redscanner 127.0.0.1

# Ports précis + détection de services
redscanner 192.168.1.10 -p 22,80,443,8080 --service-detect

# Tout un réseau local, ports 1 à 1024, export JSON
redscanner 192.168.1.0/24 -p well-known -o resultats.json

# Cibles depuis un fichier, export CSV, scan plus rapide
redscanner cibles.txt --speed fast --format csv -o resultats.csv

# Lancer comme module Python
python -m redscanner 127.0.0.1 -p 1-1024
```

### Exemple de sortie

Scan d'une machine de test locale :

```text
$ redscanner 127.0.0.1 -p 2222,8080,9 --service-detect --show-all

Hosts up: 1
  Scanning ports... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
                                 Scan Results
┏━━━━━━━━━━━┳━━━━━━┳━━━━━━━┳━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Host      ┃ Port ┃ Proto ┃ State  ┃ Service ┃ Banner                        ┃
┡━━━━━━━━━━━╇━━━━━━╇━━━━━━━╇━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 127.0.0.1 │ 9    │ tcp   │ closed │ unknown │                               │
│ 127.0.0.1 │ 2222 │ tcp   │ open   │ ssh     │ SSH-2.0-OpenSSH_9.6p1 Ubuntu  │
│ 127.0.0.1 │ 8080 │ tcp   │ open   │ http    │ HTTP/1.0 200 OK Server: nginx │
└───────────┴──────┴───────┴────────┴─────────┴───────────────────────────────┘

Scan completed in 0.01s
Open ports: 2
```

> 💡 Ajoutez ici une capture d'écran de votre terminal avec la bannière : `docs/screenshot.png`.

## Options

| Option | Description |
|---|---|
| `targets` | IP, nom d'hôte, réseau CIDR ou fichier (une cible par ligne, `#` pour commenter) |
| `-p`, `--ports` | Ports : `22,80,1-1024` ou `common` / `well-known` / `all` (défaut : `common`) |
| `--speed {slow,normal,fast}` | Préréglage concurrence/timeout : 10/5 s, 50/3 s, 200/1 s (défaut : `normal`) |
| `--concurrency N` | Nombre de connexions simultanées (prioritaire sur `--speed`) |
| `--timeout S` | Timeout de connexion en secondes (prioritaire sur `--speed`) |
| `--service-detect` | Récupère les bannières et identifie les services |
| `--no-host-discovery` | Saute la découverte d'hôtes et scanne toutes les cibles |
| `--show-all` | Affiche aussi les ports fermés et filtrés (par défaut : ports ouverts seulement) |
| `--max-hosts N` | Nombre maximum de cibles (défaut : 65536) |
| `-o`, `--output FICHIER` | Écrit les résultats dans un fichier |
| `--format {json,csv,txt}` | Format du fichier de sortie (défaut : `json`) |
| `--i-have-permission` | Confirme l'autorisation de scanner des cibles non privées |
| `--no-banner` / `--no-disclaimer` | Masque la bannière / l'avertissement |
| `--version` | Affiche la version |

**États des ports** : `open` (connexion acceptée), `closed` (connexion refusée), `filtered` (pas de réponse dans le délai, probablement un pare-feu).

## Comment ça marche

```text
Arguments → cibles + ports → confirmation (si cibles publiques)
         → découverte d'hôtes (ICMP puis TCP) → scan TCP connect (asyncio + Semaphore)
         → bannières + identification des services → tableau + export
```

```text
red-scanner/
├── pyproject.toml
├── redscanner/
│   ├── cli.py         # arguments, orchestration, affichage
│   ├── scanner.py     # moteur : sockets non bloquants + tcp_connect_scan
│   ├── discovery.py   # découverte d'hôtes (ICMP + TCP)
│   ├── services.py    # bannières et identification des services
│   ├── output.py      # formats JSON / CSV / TXT
│   ├── banner.py      # logo ASCII
│   ├── theme.py       # thème Rich et avertissement légal
│   └── data/signatures.json
└── tests/             # 48 tests pytest, sans accès internet
```

## Tests

```bash
pip install -e ".[dev]"
pytest
```

Les tests utilisent de petits serveurs locaux (`127.0.0.1`), aucun scan réseau externe.

## Différences avec nmap

| | Red Scanner | nmap |
|---|---|---|
| Techniques | TCP connect uniquement | SYN, ACK, FIN, Xmas, UDP… |
| Paquets | Connexions complètes via l'OS | Paquets bruts (droits root) |
| Détection de services | Port + quelques signatures | Des milliers de signatures et de versions |
| Détection d'OS, scripts | Non | Oui (NSE) |
| UDP | Non | Oui |

Le scan *connect* est plus simple et ne demande pas de privilèges, mais il est plus lent et plus visible dans les journaux de la cible.

## Limites connues

- TCP uniquement (pas d'UDP) ; la découverte ICMP est limitée à IPv4 (IPv6 passe par les sondes TCP)
- Sous Windows, une connexion refusée peut mettre environ 2 s à être signalée : avec un timeout inférieur (`--speed fast` = 1 s), un port fermé peut apparaître `filtered`. Préférez `--speed normal` ou `--timeout 3` ou plus
- Un hôte qui bloque ICMP **et** les ports 80, 443, 22 et 445 sera considéré éteint : utilisez `--no-host-discovery`
- Les services TLS (HTTPS…) sont identifiés par leur numéro de port, pas par leur certificat
- Les ports `postgresql`, `redis` et `telnet` n'ont pas de signature de bannière : ils sont identifiés par leur port

## Améliorations futures

- [ ] Scan SYN avec Scapy (plus rapide et plus discret)
- [ ] Vrai scan UDP (détection des réponses ICMP « port unreachable »)
- [ ] Détection de version (extraction du numéro de version dans la bannière)
- [ ] Détection de l'OS (empreinte TCP/IP)
- [ ] Support TLS (lecture du certificat sur 443/8443)

## Licence

MIT, voir [LICENSE](LICENSE).
