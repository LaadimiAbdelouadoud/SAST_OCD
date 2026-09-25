# pysast — Documentation technique

> Outil SAST (Static Application Security Testing) basé sur l'analyse de l'AST Python.
> Développé dans le cadre d'un stage à Orange Cyberdefense.

---

## Table des matières

1. [Objectif](#1-objectif)
2. [Concepts fondamentaux](#2-concepts-fondamentaux)
3. [Architecture](#3-architecture)
4. [Description des modules](#4-description-des-modules)
5. [Règles de détection (YAML)](#5-règles-de-détection-yaml)
6. [Règles de propagation du taint](#6-règles-de-propagation-du-taint)
7. [Vulnérabilités détectées](#7-vulnérabilités-détectées)
8. [Corpus de test](#8-corpus-de-test)
9. [Utilisation](#9-utilisation)
10. [Résultats de démonstration](#10-résultats-de-démonstration)
11. [Feuille de route](#11-feuille-de-route)

---

## 1. Objectif

**pysast** est un outil d'analyse statique de sécurité (SAST) pour les applications web Python. Il n'exécute jamais le code — il l'analyse uniquement à partir des sources.

### Ce que fait l'outil

1. Lit les fichiers `.py` d'un répertoire projet.
2. Parse chaque module en un **AST** (Abstract Syntax Tree).
3. Construit un **CFG** (Control Flow Graph) par fonction.
4. Exécute une **analyse de taint** (propagation de souillure) en parcourant le CFG, en suivant les données depuis les **sources** (entrées utilisateur) jusqu'aux **sinks** (fonctions dangereuses), en tenant compte des **sanitizers** (fonctions d'assainissement).
5. Génère un rapport de vulnérabilités avec : fichier/ligne, chemin source→sink, mapping CWE/OWASP, sévérité, et conseil de remédiation.

### Frameworks cibles

| Framework | Statut |
|-----------|--------|
| Flask | MVP — entièrement supporté |
| Django | Sources supportées (GET, POST, body, META) |
| FastAPI | Hors scope (Phase 5) |

### Ce que l'outil ne fait PAS

- Pas d'analyse dynamique (DAST) — purement statique.
- Pas d'analyse inter-procédurale dans le MVP (Phase 1–2) — chaque fonction est analysée indépendamment.
- Pas d'analyse des templates Jinja2 (Phase 5).
- Zéro faux positif est un objectif impossible pour un SAST ; la précision est mesurée et tracée.

---

## 2. Concepts fondamentaux

Ces quatre représentations se construisent les unes sur les autres. Comprendre leur relation est ce qui différencie un vrai moteur de taint d'un simple grep.

### 2.1 AST — ce que le programme *est*

L'**Abstract Syntax Tree** est l'arbre syntaxique du code source. Chaque nœud représente une construction syntaxique (`Assign`, `Call`, `If`, `BinOp`…). Il capture la **structure** du code, pas son exécution.

Python fournit l'AST directement via le module `ast` de la bibliothèque standard :

```python
import ast
tree = ast.parse("uid = request.args.get('id')")
# tree.body[0] → Assign(targets=[Name('uid')], value=Call(...))
```

### 2.2 CFG — comment le programme *s'exécute*

Le **Control Flow Graph** est un graphe orienté où :
- Les **nœuds** sont des blocs de base (séquences d'instructions sans branchement).
- Les **arêtes** représentent les transitions d'exécution possibles.

Un `if` produit deux branches qui se rejoignent après ; une boucle `while` crée une arête arrière. Le CFG capture le **flux de contrôle**.

```
┌─────────────┐
│  uid = ...  │  ← bloc d'entrée
└──────┬──────┘
       ▼
┌─────────────────┐     ┌──────────────┐
│  if uid > 0:    │────▶│  (then) ...  │
└─────────────────┘     └──────┬───────┘
       │ (else)                │
       ▼                       ▼
┌──────────────┐        ┌─────────────┐
│  (else) ...  │───────▶│  (merge)    │
└──────────────┘        └─────────────┘
```

### 2.3 DFG — comment les *données* circulent

Le **Data Flow Graph** relie chaque **définition** d'une variable (là où elle reçoit une valeur) à chaque **utilisation** de cette variable. Le taint voyage conceptuellement sur ces arêtes : si `uid` est souillé et `q = "..." + uid`, alors `q` est souillé.

### 2.4 Relation entre CFG et DFG — la clarification clé

> **Le moteur parcourt physiquement le CFG. Le flux de données est calculé *pendant* ce parcours par les fonctions de transfert ; le DFG est implicite, pas un objet séparé en mémoire.**

- Le **CFG fournit le squelette de parcours** : quels nœuds visiter, dans quel ordre, et où les branches convergent (les états de taint provenant de plusieurs chemins entrants sont **joints par union** aux points de convergence).
- À chaque nœud, une **fonction de transfert** applique la logique de flux de données (`q` dépend de `uid` → propagation du taint).

Pipeline conceptuel :

```
AST  →  CFG  →  définitions atteignantes (calculées sur le CFG)
                      │
                      ▼
              chaînes def-use (le DFG, souvent implicite)
                      │
                      ▼
              propagation du taint (point fixe sur liste de travail)
```

---

## 3. Architecture

```
                ┌──────────────┐
  Dossier     → │  Ingestion   │  parcourt les .py, construit la carte des modules
  projet        └──────┬───────┘
                       ▼
                ┌──────────────┐
                │   Parser     │  module ast → AST par module
                └──────┬───────┘
                       ▼
                ┌──────────────┐
                │ Table des    │  résolution des imports :
                │ symboles     │  nom local → nom qualifié
                └──────┬───────┘
                       ▼
                ┌──────────────┐
                │ CFG Builder  │  AST → graphe de flux de contrôle par fonction
                └──────┬───────┘
                       ▼
                ┌──────────────┐
                │ Moteur de    │  point fixe sur liste de travail ;
                │ Taint        │  fonctions de transfert propagent le taint ;
                │              │  correspond aux sources/sinks/sanitizers du YAML
                └──────┬───────┘
                       ▼
                ┌──────────────┐
                │  Reporter    │  findings → texte / JSON / SARIF / HTML
                └──────────────┘
```

### Choix de bibliothèques

| Composant | Bibliothèque | Justification |
|-----------|-------------|---------------|
| AST | `ast` (stdlib Python) | Pédagogique, correspond à PyT, pas de dépendance externe |
| CFG | Implémentation maison | Meilleure compréhension, contrôle total |
| Configuration | `PyYAML` | Format lisible pour la base de connaissances |
| CLI | `click` | Interface ergonomique, gestion des erreurs intégrée |
| Sortie | `json` stdlib + SARIF | Compatible outils CI/CD (GitHub Code Scanning) |

---

## 4. Description des modules

### Structure du projet

```
pysast/
├── pysast/
│   ├── __init__.py          # version du package
│   ├── __main__.py          # point d'entrée : python -m pysast
│   ├── cli.py               # CLI (click) : commande scan
│   ├── ingestion.py         # découverte et lecture des fichiers .py
│   ├── parser.py            # source → AST (ast.parse)
│   ├── symbols.py           # résolution des imports → nom qualifié
│   ├── findings.py          # modèle Finding / FlowStep
│   ├── cfg/
│   │   ├── node.py          # structures CFGNode, CFG
│   │   └── builder.py       # AST → CFG par fonction
│   ├── taint/
│   │   ├── lattice.py       # TaintLabel, TaintState, join()
│   │   ├── matching.py      # correspondance patterns AST ↔ règles YAML
│   │   ├── transfer.py      # fonctions de transfert par type de stmt
│   │   └── engine.py        # point fixe sur liste de travail
│   ├── knowledge/
│   │   ├── loader.py        # chargement et validation du YAML
│   │   └── default_rules.yaml  # catalogue sources/sinks/sanitizers
│   └── reporters/
│       ├── text.py          # sortie texte colorée (CLI)
│       ├── json_reporter.py # sérialisation JSON
│       ├── sarif.py         # format SARIF 2.1.0 (CI/GitHub)
│       └── html.py          # rapport HTML autonome
├── tests/
│   ├── vulnerable_samples/  # applications Flask intentionnellement vulnérables
│   ├── safe_samples/        # applications Flask sûres (doivent produire 0 finding)
│   └── test_*.py            # tests unitaires et d'intégration
├── pyproject.toml
└── README.md
```

### `ingestion.py`

Découvre tous les fichiers `.py` d'un répertoire (récursivement), en ignorant `__pycache__`, `.venv`, `.git`, etc. Gère les encodages UTF-8 et latin-1.

### `parser.py`

Enveloppe `ast.parse`. Lève `ParseError` (qui hérite d'`Exception`) en cas d'erreur de syntaxe, avec le nom du fichier et le message d'erreur Python.

### `symbols.py` — résolution des imports

**Problème :** une règle dit `os.system`, mais le même appel peut apparaître sous plusieurs formes :

```python
import os;              os.system(x)    # → "os.system"
from os import system;  system(x)       # → Name "system" seul
import os as o;         o.system(x)     # → "o.system" (alias)
from flask import request               # → "flask.request"
```

**Solution :** avant toute correspondance, construire une table des symboles `nom_local → nom_qualifié` en parcourant les nœuds `Import` et `ImportFrom` de l'AST.

```python
# Exemple : from flask import request
symbol_table = {"request": "flask.request"}

# Résolution de request.args.get('id')
# → Attribute(attr="get", value=Attribute(attr="args", value=Name("request")))
# → "flask.request.args.get"
```

### `cfg/builder.py`

Construit le CFG d'une fonction en traitant chaque type de statement :

| Statement | Comportement |
|-----------|-------------|
| Instruction simple | Ajoutée au bloc courant |
| `if/else` | Deux branches, nœud de fusion après |
| `while/for` | Nœud d'en-tête avec arête arrière (back-edge) |
| `return` | Termine le bloc, marque comme nœud de sortie |
| `try/except` | Traitement conservatif (corps comme séquence) |

### `taint/lattice.py`

Définit l'état abstrait de l'analyse :

```python
@dataclass(frozen=True)
class TaintLabel:
    source_id: str           # identifiant de la source (ex: "flask-request-args")
    vuln_classes: frozenset  # classes de vulnérabilité concernées (ex: {"sqli", "xss"})
    origin_file: str         # fichier d'origine
    origin_line: int         # ligne d'origine

# État de taint : variable → ensemble de labels
TaintState = dict[str, set[TaintLabel]]
```

La **jonction** (join) de deux états aux points de convergence du CFG est l'**union** : `join(a, b)` retourne tous les labels de `a` et `b`.

### `taint/matching.py`

Deux philosophies de correspondance (compromis précision/rappel) :

| Pattern | Exemple | Mécanisme | Avantage | Inconvénient |
|---------|---------|-----------|----------|--------------|
| Nom qualifié | `os.system` | Résolution via table des symboles | Précis, peu de faux positifs | Nécessite la résolution des imports |
| Heuristique méthode | `*.execute` | Correspondance sur `call.func.attr` | Haute couverture | Faux positifs possibles |

### `taint/transfer.py`

Fonctions de transfert — comment le taint se propage à chaque instruction :

| Type d'instruction | Comportement |
|---------------------|-------------|
| `x = expr` | `x` hérite du taint de `expr` |
| `x += expr` | Union du taint de `x` et de `expr` |
| `f(args)` source | Résultat souillé avec les labels de la source |
| `f(args)` sanitizer | Supprime les classes de vuln assainies des labels |
| `f(args)` sink | Émet un Finding si `tainted_args[i]` est souillé |
| `return f(args)` | Vérifie également les sinks dans les returns |

### `taint/engine.py`

Algorithme de point fixe sur liste de travail :

```
1. Initialiser tous les états d'entrée à {}
2. Ajouter le nœud d'entrée à la liste de travail
3. Tant que la liste de travail est non vide :
   a. Extraire un nœud
   b. Pour chaque instruction : appliquer la fonction de transfert
   c. Pour chaque successeur : joindre l'état sortant avec l'état d'entrée existant
   d. Si l'état a changé : remettre le successeur dans la liste de travail
4. Retourner tous les findings émis
```

Les **boucles** sont traitées naturellement : l'arête arrière remet des nœuds dans la liste de travail jusqu'à ce que les états se stabilisent (point fixe).

---

## 5. Règles de détection (YAML)

La base de connaissances est dans `pysast/knowledge/default_rules.yaml`. C'est la **seule** chose à modifier pour ajouter une classe de vulnérabilité — sans toucher au moteur.

### Schéma d'une règle

```yaml
sources:
  - id: flask-request-args
    framework: flask
    vuln_classes: [sqli, cmdi, xss, path-traversal, ssrf, open-redirect]
    patterns:
      - "flask.request.args"
      - "flask.request.args.get"
      - "flask.request.values"

sinks:
  - id: sqli-execute
    vulnerability: "SQL Injection"
    cwe: "CWE-89"
    owasp: "A03:2021-Injection"
    severity: HIGH
    cvss_v31: 8.6
    vuln_class: sqli
    remediation: "Utiliser des requêtes paramétrées..."
    patterns:
      - "*.execute"      # heuristique méthode
      - "*.executemany"
    tainted_args: [0]    # seul l'argument 0 est dangereux

  - id: cmdi-subprocess
    ...
    patterns: ["subprocess.run", "subprocess.call", "subprocess.Popen"]
    tainted_args: [0]
    conditions:          # sink UNIQUEMENT si shell=True
      - kwarg: shell
        equals: true

sanitizers:
  - id: int-cast
    patterns: ["int", "float"]
    clears: [sqli, cmdi, xss, path-traversal, code-injection]
```

### `tainted_args` — réducteur de faux positifs clé pour SQLi

```python
cursor.execute("SELECT * FROM u WHERE id=" + uid)     # VULNÉRABLE : uid en arg 0
cursor.execute("SELECT * FROM u WHERE id=%s", (uid,)) # SÛR : uid en arg 1 (paramétré)
```

Avec `tainted_args: [0]`, un finding n'est émis que si le taint atteint l'argument 0. La forme paramétrée passe silencieusement.

### `conditions` — sinks conditionnels

```python
subprocess.run(cmd)               # pas un sink (pas de shell)
subprocess.run(cmd, shell=True)   # sink : finding émis
yaml.load(data)                   # sink : finding émis
yaml.load(data, Loader=SafeLoader) # condition non remplie → pas de finding
```

---

## 6. Règles de propagation du taint

Ces règles sont dans `pysast/taint/transfer.py`. Contrairement aux règles de détection (données YAML), ce sont des **règles de code** — rarement modifiées.

| Expression | Propagation |
|------------|-------------|
| `x = tainted_expr` | `x` est souillé |
| `x += tainted_expr` | `x` reçoit l'union |
| `"..." + tainted` | résultat souillé (concaténation) |
| `f"...{tainted}..."` | résultat souillé (f-string) |
| `"...{}".format(tainted)` | résultat souillé (méthode) |
| `"..." % tainted` | résultat souillé (formatage %) |
| `tainted[i]`, `tainted.attr` | résultat souillé (conservatif) |
| `sanitizer(tainted)` | taint nettoyé pour les classes concernées |
| `sink(tainted_arg_0)` | **Finding émis** |

---

## 7. Vulnérabilités détectées

| # | Vulnérabilité | CWE | OWASP | Sévérité | CVSS v3.1 |
|---|---------------|-----|-------|----------|-----------|
| 1 | SQL Injection | CWE-89 | A03:2021 | HIGH | 8.6 |
| 2 | Command Injection | CWE-78 | A03:2021 | CRITICAL | 9.8 |
| 3 | Code Injection | CWE-94 | A03:2021 | CRITICAL | 9.8 |
| 4 | Cross-Site Scripting (XSS) | CWE-79 | A03:2021 | HIGH | 7.4 |
| 5 | Path Traversal | CWE-22 | A01:2021 | HIGH | 7.5 |
| 6 | SSRF | CWE-918 | A10:2021 | HIGH | 8.6 |
| 7 | Insecure Deserialization | CWE-502 | A08:2021 | CRITICAL | 9.8 |
| 8 | Open Redirect | CWE-601 | A01:2021 | MEDIUM | 6.1 |

### Sources d'entrée surveillées

**Flask :**
- `request.args`, `request.args.get` — paramètres URL
- `request.form`, `request.form.get` — données POST
- `request.json`, `request.get_json` — corps JSON
- `request.data` — corps brut
- `request.cookies`, `request.headers` — cookies et en-têtes
- `request.files` — fichiers uploadés

**Django :**
- `request.GET`, `request.POST` — paramètres GET/POST
- `request.body` — corps brut
- `request.META` — métadonnées HTTP
- `request.FILES` — fichiers uploadés

---

## 8. Corpus de test

Chaque classe de vulnérabilité possède deux types d'échantillons de test :

### Échantillons vulnérables

Petites applications Flask multi-fichiers (`app.py` + `views.py`) avec des vulnérabilités intentionnelles annotées.

| Dossier | Vulnérabilité | Pattern testé |
|---------|--------------|---------------|
| `flask_sqli/` | SQLi | `cursor.execute("..." + uid)` |
| `flask_cmdi/` | CmdI | `subprocess.run(cmd, shell=True)` |
| `flask_xss/` | XSS | `render_template_string("<h1>" + name)` |
| `flask_code_injection/` | Code Injection | `eval(expr)` |
| `flask_path_traversal/` | Path Traversal | `open(filename)` |
| `flask_ssrf/` | SSRF | `requests.get(url)` |
| `flask_deserialization/` | Deserialization | `pickle.loads(raw)` |
| `flask_open_redirect/` | Open Redirect | `redirect(next_url)` |

### Échantillons sûrs (vrais négatifs critiques)

Ces échantillons **doivent produire zéro finding** — c'est là que la précision est gagnée ou perdue.

| Dossier | Mitigation testée | Pourquoi c'est sûr |
|---------|-------------------|-------------------|
| `flask_sqli_safe/` | Requête paramétrée | `uid` en arg 1, pas arg 0 |
| `flask_cmdi_safe/` | Pas de `shell=True` | Condition `shell=True` non remplie |
| `flask_xss_safe/` | `markupsafe.escape()` | Sanitizer nettoie le taint XSS |
| `flask_code_injection_safe/` | Cast `int()` | Sanitizer nettoie tous les taints d'injection |
| `flask_path_traversal_safe/` | `secure_filename()` | Sanitizer nettoie path-traversal |
| `flask_ssrf_safe/` | URL codée en dur | Aucun taint utilisateur n'atteint `requests.get` |
| `flask_deserialization_safe/` | `json.loads` | Pas un sink dangereux |
| `flask_open_redirect_safe/` | `url_for()` | Aucun taint utilisateur dans `redirect()` |

### Résultats des tests

```
46 tests : 46 passés, 0 échoués
- 4  tests CFG
- 4  tests ingestion
- 3  tests parser
- 8  tests table des symboles
- 27 tests d'intégration taint (détection + vrais négatifs + propagation)
```

---

## 9. Utilisation

### Installation

```bash
cd pysast/
pip install -e ".[dev]"
```

### Lancement

```bash
# Depuis le répertoire du projet
python -m pysast --help
python -m pysast scan chemin/vers/app/
python -m pysast scan chemin/vers/app/ --format json --output results.json
python -m pysast scan chemin/vers/app/ --format html  --output report.html
python -m pysast scan chemin/vers/app/ --format sarif --output results.sarif
```

### Options

| Option | Description |
|--------|-------------|
| `--format text\|json\|sarif\|html` | Format de sortie (défaut : `text`) |
| `--output FILE` | Écrire dans un fichier au lieu de stdout |
| `--rules FILE` | Utiliser un fichier YAML de règles personnalisé |
| `--no-color` | Désactiver les couleurs ANSI |

### Code de sortie

| Code | Signification |
|------|--------------|
| `0` | Aucun finding — application sûre selon les règles |
| `1` | Au moins un finding — intégration CI possible |

### Exemple de sortie texte

```
[1] CRITICAL — Command Injection (CWE-78)
    File  : app/views.py:14
    Rule  : PYSAST-CMDI-SUBPROCESS
    OWASP : A03:2021-Injection
    Sink  : subprocess.run(cmd, shell=True, capture_output=True, text=True)
    Flow  :
      app/views.py:12  cmd
      app/views.py:14  subprocess.run(cmd, shell=True, capture_output=True, text=True)
    Fix   : Passer une liste d'arguments à subprocess et supprimer shell=True.

[2] HIGH — SQL Injection (CWE-89)
    ...

2 finding(s).
```

### Exemple de finding JSON

```json
{
  "rule_id": "PYSAST-SQLI-EXECUTE",
  "vulnerability": "SQL Injection",
  "cwe": "CWE-89",
  "owasp": "A03:2021-Injection",
  "severity": "HIGH",
  "cvss_v31": 8.6,
  "file": "app/views.py",
  "sink_line": 17,
  "sink_snippet": "cursor.execute(query)",
  "source": {"file": "app/views.py", "line": 14, "code": "uid"},
  "data_flow": [
    {"file": "app/views.py", "line": 14, "code": "uid"},
    {"file": "app/views.py", "line": 17, "code": "cursor.execute(query)"}
  ],
  "remediation": "Utiliser des requêtes paramétrées..."
}
```

---

## 10. Résultats de démonstration

Scan des 8 applications vulnérables de test :

```
python -m pysast scan tests/vulnerable_samples --no-color
```

| # | Sévérité | Vulnérabilité | Fichier | Ligne |
|---|----------|---------------|---------|-------|
| 1 | CRITICAL | Command Injection (CWE-78) | flask_cmdi/views.py | 16 |
| 2 | CRITICAL | Code Injection (CWE-94) | flask_code_injection/views.py | 14 |
| 3 | CRITICAL | Insecure Deserialization (CWE-502) | flask_deserialization/views.py | 16 |
| 4 | MEDIUM | Open Redirect (CWE-601) | flask_open_redirect/views.py | 14 |
| 5 | HIGH | Path Traversal (CWE-22) | flask_path_traversal/views.py | 14 |
| 6 | HIGH | SQL Injection (CWE-89) | flask_sqli/views.py | 17 |
| 7 | HIGH | SSRF (CWE-918) | flask_ssrf/views.py | 15 |
| 8 | HIGH | XSS (CWE-79) | flask_xss/views.py | 15 |

Scan des 8 applications sûres :

```
python -m pysast scan tests/safe_samples --no-color
→ No findings.  (exit 0)
```

**Précision sur le corpus de test : 100% (0 faux positif, 8/8 vrais positifs détectés)**

---

## 11. Feuille de route

| Phase | Statut | Contenu |
|-------|--------|---------|
| **Phase 0** | ✅ Terminé | Scaffold, CI, corpus de test ground-truth |
| **Phase 1** | ✅ Terminé | MVP intraprocédural — SQLi + CmdI |
| **Phase 2** | ✅ Terminé | Toutes les 8 classes de vuln, 46 tests |
| **Phase 3** | 🔲 À faire | Analyse interprocédurale (résumés de fonctions) |
| **Phase 4** | 🔲 À faire | SARIF + CI GitHub Actions, métriques précision/rappel |
| **Phase 5** | 🔲 À faire | Django/FastAPI complets, templates Jinja2 |

### Phase 3 — Analyse interprocédurale

Dans le MVP actuel, chaque fonction est analysée de façon **indépendante** (intraprocédurale). Si une fonction helper `get_user_id()` retourne une valeur souillée et qu'une autre fonction passe ce résultat à un sink, la vulnérabilité n'est pas détectée.

La Phase 3 introduira des **résumés de fonctions** (function summaries) : pour chaque fonction, calculer quels arguments souillés en entrée produisent des valeurs souillées en sortie, puis propager ce résumé aux sites d'appel.

---

*Outil développé par Abdelouadoud Laadimi — Stage Orange Cyberdefense 2025*
