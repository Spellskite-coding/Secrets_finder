# secrets-finder

Un scanner rapide et à faible taux de faux positifs pour les identifiants codés en dur dans les arborescences de code source.
Fichier unique, bibliothèque standard uniquement, Python 3.10+.

```bash
python3 secrets_finder.py .                       # scanner l'arborescence courante
python3 secrets_finder.py . --git-tracked         # uniquement les fichiers suivis par git
python3 secrets_finder.py . -f sarif -o out.sarif # GitHub Code Scanning
python3 secrets_finder.py --self-test             # vérifier les 57 règles
```

## Résultats mesurés

Benchmark réalisé sur `/usr/lib/python3.13` — 627 fichiers texte, 11,2 Mo,
303 452 lignes — sur 8 cœurs. Les temps correspondent au minimum de 5
exécutions à cache chaud, les trois mesurées consécutivement.

| | règles | temps | accélération | résultats |
|---|---|---|---|---|
| boucle naïve ligne×motif | 11 | 18,55 s | — | **348** (quasiment tous faux) |
| secrets-finder `-j 1` | 59 | 5,08 s | 3,7× | 1 |
| secrets-finder `-j 8` | 59 | **1,31 s** | **14,1×** | **1** |

**14× plus rapide tout en évaluant 5× plus de règles, et 348 résultats ramenés à 1.**

Les temps absolus dépendent de la charge de la machine — une seconde exécution
du même benchmark sur une machine inactive a donné 7,94 s / 2,08 s / 0,57 s.
Les ratios étaient identiques à 2 % près, donc c'est l'accélération qu'il faut
retenir, pas les secondes.

Le seul résultat restant est `passwd='geheim$parole'` dans une docstring
`urllib.request` — un véritable mot de passe littéral dans le code source,
au sein d'une documentation d'exemple. On peut soutenir qu'il s'agit d'une
correspondance correcte plutôt que d'un faux positif ; le supprimer
nécessiterait une analyse syntaxique des commentaires par langage, ce que le
scanner ne tente délibérément pas de faire.

Le rappel (recall) est vérifié séparément : un corpus avec un identifiant
planté par règle obtient un score de **59/59**, sans aucun doublon signalé.

### Sur d'autres arborescences réelles

| arborescence | résultats | évaluation |
|---|---|---|
| `/usr/lib/python3.13` | 1 | un mot de passe littéral dans une docstring |
| `/usr/share/doc` | 13 | 10 sont de vrais fichiers de clés PEM (clés d'exemple OpenVPN/aiohttp) |
| `/etc` | 1 | un en-tête PEM au sein d'un motif MIME magique ImageMagick |

Le résultat dans `/etc` pourrait être éliminé en ancrant le motif de clé
privée au début d'une ligne, et cela n'a délibérément pas été fait : dans la
documentation HTML d'OpenVPN, ce même en-tête *est* en début de ligne, donc
un ancrage ne réglerait pas la catégorie, et cela ferait perdre les clés
intégrées dans le code source sous forme de littéraux de chaîne
(`KEY = "-----BEGIN RSA PRIVATE KEY-----\n..."`), ce qui constitue une vraie
fuite. Une dismission de triage à bas coût vaut mieux qu'une clé manquée.

## Pourquoi c'est rapide

Le profilage de l'implémentation naïve a montré que 83 % du temps
d'exécution se trouvait dans un seul appel — la correspondance de motif sur
chaque ligne. Trois changements expliquent cet écart :

1. **Pré-filtrage par mots-clés.** Chaque règle déclare des mots-clés
   littéraux peu coûteux (`akia`, `ghp_`, `private key`). Une seule regex
   combinée rejette les lignes qui ne peuvent correspondre à aucune règle ;
   seules les survivantes — 1,4 % des lignes ici — sont testées contre le
   petit sous-ensemble de règles dont les mots-clés sont effectivement
   présents.

2. **Pas de `re.IGNORECASE` sur le chemin critique.** Le repli sur la casse
   met en échec le scan littéral du moteur de regex. Mettre chaque ligne en
   minuscules une seule fois puis faire correspondre un déclencheur sensible
   à la casse est **7× plus rapide**, et la chaîne mise en minuscules est
   ensuite réutilisée pour le pragma d'ignorance et la recherche de
   candidats.

3. **Multiprocessing, correctement fait.** Le module `re` de Python ne
   libère pas le GIL, donc le scan est véritablement limité par le CPU et
   les threads n'aideraient pas. Les workers compilent le jeu de règles une
   seule fois dans un initialiseur, donc chaque tâche ne transmet qu'une
   chaîne de chemin. En dessous de 200 fichiers, le pool coûte plus qu'il
   ne fait gagner et le scan s'exécute en ligne.

## Pourquoi c'est silencieux

Les 348 résultats de la version naïve provenaient de motifs incapables de
distinguer un identifiant d'un texte ordinaire. Quatre filtres les
remplacent :

- **Motifs structurels.** Correspondre à la forme documentée d'un
  identifiant (`AKIA` + 16 caractères majuscules) plutôt qu'à un mot anglais
  à proximité.
- **Entropie.** Chaque règle capture le secret lui-même dans le groupe 1,
  donc l'entropie de Shannon est mesurée sur l'identifiant seul, pas sur le
  texte environnant.
- **Rejet des valeurs de substitution (placeholders).**
  `AKIAIOSFODNN7EXAMPLE`, `<your-token>`, `${API_KEY}`, `xxxxxxxx` et
  consorts.
- **Rejet des références de code.** Appliqué uniquement aux règles qui
  correspondent sur un *nom* de variable (`API_TOKEN = ...`) : une valeur
  qui est un identifiant qualifié ou un appel de fonction est du code, pas
  un identifiant secret. À elle seule, cette règle a éliminé 3 des 4 faux
  positifs restants.

Les résultats qui se chevauchent sont fusionnés — une clé de service
Supabase est aussi un JWT valide, et rapporter les deux revient à compter
deux fois le même secret. La règle la plus spécifique l'emporte.

## Comportement notable

- **Les secrets sont expurgés (redacted) par défaut**, dans tous les formats
  de sortie y compris l'extrait de contexte. Un rapport de scan est sinon
  lui-même un artefact porteur de secrets qui finit dans les logs CI et les
  tickets. `--show-secrets` permet de désactiver ce comportement.
- **Les fichiers minifiés sont quand même scannés.** Les lignes trop longues
  sont découpées en fenêtres qui se chevauchent plutôt que d'être ignorées,
  donc une clé intégrée à la colonne 320 004 d'un bundle sur une seule
  ligne est quand même trouvée, sans le coût de faire correspondre la ligne
  entière d'un coup.
- **Les binaires sont ignorés** par extension, puis en sondant les 8 premiers
  Ko à la recherche d'octets NUL.
- **Les fichiers UTF-16 et UTF-32 sont scannés, pas ignorés.** Ces
  encodages complètent l'ASCII avec des octets NUL, donc la sonde binaire
  les rejette à première vue — et PowerShell, .NET et les exports de
  registre émettent couramment de l'UTF-16LE. Les BOM sont reconnus, et
  l'UTF-16 sans BOM est déduit par l'alternance. Cette déduction vérifie
  *les deux côtés* de chaque paire d'octets : un en-tête ELF est composé
  d'environ 82 % de NUL, la plupart sur des positions impaires, ce qui imite
  parfaitement l'UTF-16LE, et seule l'exigence que l'autre côté soit du
  texte imprimable permet de les distinguer.
- **Les liens symboliques ne sont pas suivis par défaut.** Avec
  `--follow-symlinks`, les répertoires et fichiers sont suivis par
  `(device, inode)`, donc un cycle de liens symboliques est détecté plutôt
  que laissé au `ELOOP` du noyau après environ 40 niveaux, et un fichier
  accessible via plusieurs chemins est signalé une seule fois au lieu d'une
  fois par chemin. Le chemin par défaut évite entièrement les appels
  `stat()` supplémentaires.
- **`--git-tracked`** délègue à `git ls-files` plutôt que de réimplémenter
  la sémantique de `.gitignore`.
- **Les baselines** (`--write-baseline` / `--baseline`) suppriment les
  résultats connus par empreinte (fingerprint), ce qui permet d'adopter un
  scan sur une base de code existante.
- **Liste d'autorisation en ligne (allowlisting)** via
  `pragma: allowlist secret`.

## Codes de sortie

| code | signification |
|---|---|
| 0 | aucun résultat au niveau ou au-dessus de `--fail-on` |
| 1 | résultats signalés |
| 2 | erreur d'utilisation ou d'E/S — *le scan ne s'est pas exécuté* |

Le fait de distinguer 1 et 2 permet à la CI de différencier « cette branche
fuite une clé » de « le scanner était mal configuré ».

## Règles

59 détecteurs couvrant le cloud (AWS, GCP, Azure, DigitalOcean, Cloudflare),
les VCS (GitHub, GitLab), l'IA (OpenAI, Anthropic, Hugging Face), les
paiements (Stripe, Square, PayPal, Shopify), la messagerie (Slack, Discord,
Telegram, Twilio, SendGrid), les paquets (npm, PyPI, RubyGems, Docker Hub),
l'infrastructure (Vault, Terraform, Grafana, Datadog, Sentry), ainsi que les
clés privées, les JWT, les URI de base de données et les affectations
génériques.

`--list-rules` les affiche avec leur sévérité, leurs mots-clés et leurs
seuils d'entropie.

Chaque règle porte son propre faux identifiant structurellement valide
comme vecteur de test. `--self-test` vérifie que chaque règle correspond à
son vecteur *et* qu'un corpus de code propre ne produit aucun résultat,
afin qu'une regex resserrée pour la précision ne puisse pas cesser
silencieusement de détecter quoi que ce soit. Les exemples sont générés
plutôt qu'écrits à la main, car un jeton de 82 caractères compté à la main
est la façon dont un vecteur de test se dégrade silencieusement.

## Tests

`--self-test` ne nécessite aucune dépendance et couvre les règles. La suite
pytest couvre tout le reste — 305 tests, ~1,7 s.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install pytest
python -m pytest
```

Elle est organisée par propriété testée plutôt que par fonction : rappel,
précision, expurgation (redaction), robustesse, découverte, suppression des
chevauchements, intégrité du jeu de règles, entropie, déterminisme sous
multiprocessing, et contrat de la CLI.

### Rompre la circularité

`--self-test` fait correspondre chaque règle à `rule.example` — la chaîne
même pour laquelle la regex a été écrite. C'est circulaire : un motif
codant une mauvaise idée du format d'un fournisseur est faux *en même
temps que* son exemple, et le test passe quand même.

`tests/realistic_corpus.py` existe pour rompre cette boucle. Il compose des
identifiants à partir de la forme documentée de chaque fournisseur avec du
contenu aléatoire issu d'un flux sans rapport, et les écrit dans les types
de fichiers d'où les identifiants fuient réellement — `.env`, `Dockerfile`,
`main.tf`, `.gitlab-ci.yml`, `.npmrc`, XML, propriétés Java, scripts shell.
Une règle qui ne tolère silencieusement que `key = "value"` échoue là plutôt
qu'en production. `test_corpus_covers_every_rule` empêche le corpus de
prendre du retard sur le jeu de règles.

La limite irréductible : ces formes proviennent de la documentation, pas
d'identifiants réels en circulation. Si une forme est fausse ici, elle est
probablement fausse dans la règle aussi. Les entrées qui n'ont pas pu être
confirmées sont marquées `UNVERIFIED` dans ce module.

Plusieurs tests existent parce que le comportement qu'ils figent était
autrefois erroné :

- `test_symlink_same_file_reported_once` — un secret accessible via un
  fichier, un lien symbolique vers celui-ci et un lien symbolique vers son
  répertoire était signalé trois fois.
- `test_symlink_cycle_terminates` — un cycle de répertoires provoquait
  auparavant une récursion jusqu'à ce que le noyau lève `ELOOP` à environ
  40 niveaux.
- `test_real_credentials_are_not_mistaken_for_placeholders` — l'heuristique
  de faible variété évoluait avec la longueur, donc un jeton hexadécimal de
  146 caractères ressemblait à du remplissage et était écarté.
- `test_oversized_file_is_skipped` — avec un `--max-file-size` inférieur à
  la sonde binaire de 8 Ko, la longueur de lecture suivante devenait
  négative et levait une erreur, classant un fichier trop volumineux comme
  « illisible ».
- `test_overlapping_windows_do_not_double_report` — les fenêtres de scan se
  chevauchent par conception, donc le même secret peut correspondre deux
  fois et doit être fusionné.
- `test_encoding_variants[utf-16-le]` — les fichiers UTF-16 étaient
  classés comme binaires et jamais scannés.
- `test_elf_header_is_not_mistaken_for_utf16` — le premier correctif pour
  le point précédent faisait lire chaque binaire ELF comme du texte UTF-16.
- `test_credential_starting_with_punctuation_is_not_dropped` — le filtre de
  valeurs de substitution rejetait toute valeur commençant par `$`, `%`,
  `(`, `[` ou `<`, sous prétexte qu'il s'agissait de syntaxe de gabarit,
  écartant silencieusement des mots de passe robustes.
- `test_email_address_is_not_a_password` — `passwd="anonymous@domain.org"`,
  la convention FTP anonyme, était signalé comme mot de passe codé en dur.

Tout ce qui suit `test_overlapping_windows_do_not_double_report` a été
découvert par la suite de tests ou le corpus réaliste, et non par des tests
manuels.

`test_no_format_leaks_the_secret_by_default` est celui à conserver si l'on
n'en garde qu'un seul : il grep chaque format de sortie à la recherche de
l'identifiant brut.

## Idées non implémentées

- Scanner l'historique git (`git log -p`) — les secrets survivent à la
  suppression dans les commits.
- Validation en direct des identifiants, comme le fait TruffleHog.
  Délibérément omis : cela impliquerait d'envoyer les identifiants
  découverts à des API tierces.
