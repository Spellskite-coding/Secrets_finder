# secrets-finder

A fast, low-false-positive scanner for credentials hardcoded in source trees.
Single file, standard library only, Python 3.10+.

```bash
python3 secrets_finder.py .                       # scan the current tree
python3 secrets_finder.py . --git-tracked         # only files git knows about
python3 secrets_finder.py . -f sarif -o out.sarif # GitHub Code Scanning
python3 secrets_finder.py --self-test             # verify all 57 rules
```

## Measured results

Benchmarked against `/usr/lib/python3.13` — 627 text files, 11.2 MB, 303,452
lines — on 8 cores. Timings are the minimum of 5 warm-cache runs, all three
measured back to back.

| | rules | time | speed-up | findings |
|---|---|---|---|---|
| naive line×pattern loop | 11 | 18.55 s | — | **348** (essentially all false) |
| secrets-finder `-j 1` | 59 | 5.08 s | 3.7× | 1 |
| secrets-finder `-j 8` | 59 | **1.31 s** | **14.1×** | **1** |

**14× faster while evaluating 5× more rules, and 348 findings down to 1.**

Absolute timings depend on machine load — a second run of the same benchmark on
an idle machine gave 7.94 s / 2.08 s / 0.57 s. The ratios were identical to
within 2%, so the speed-up is the number worth quoting, not the seconds.

The single remaining finding is `passwd='geheim$parole'` in a `urllib.request`
docstring — a real password literal in the source, in example documentation.
That is arguably a correct match rather than a false positive; suppressing it
would need per-language comment parsing, which the scanner deliberately does
not attempt.

Recall is verified separately: a corpus with one planted credential per rule
scores **59/59**, with zero duplicate reports.

### On other real trees

| tree | findings | assessment |
|---|---|---|
| `/usr/lib/python3.13` | 1 | a password literal in a docstring |
| `/usr/share/doc` | 13 | 10 are real PEM key files (OpenVPN/aiohttp sample keys) |
| `/etc` | 1 | a PEM header inside an ImageMagick MIME magic pattern |

The `/etc` hit could be removed by anchoring the private-key pattern to the
start of a line, and that was deliberately not done: in the OpenVPN HTML docs
the same header *is* at the start of a line, so anchoring would not fix the
category, and it would lose keys embedded in source as string literals
(`KEY = "-----BEGIN RSA PRIVATE KEY-----\n..."`), which is a genuine leak
pattern. One cheap triage dismissal beats a missed key.

## Why it is fast

Profiling the obvious implementation showed 83% of runtime inside a single
call — the pattern match against each line. Three changes account for the gap:

1. **Keyword pre-filtering.** Every rule declares cheap literal keywords
   (`akia`, `ghp_`, `private key`). One combined regex rejects lines that
   cannot match any rule; only the survivors — 1.4% of lines here — are tested
   against the small subset of rules whose keywords are actually present.

2. **No `re.IGNORECASE` on the hot path.** Case folding defeats the regex
   engine's literal scan. Lowercasing each line once and matching a
   case-sensitive trigger is **7× faster**, and the lowered string is then
   reused for the ignore pragma and the candidate lookup.

3. **Multiprocessing, correctly.** Python's `re` does not release the GIL, so
   scanning is genuinely CPU-bound and threads would not help. Workers compile
   the ruleset once in an initializer, so each task ships only a path string.
   Below 200 files the pool costs more than it saves and the scan runs inline.

## Why it is quiet

The naive version's 348 findings came from patterns that cannot distinguish a
credential from ordinary text. Four filters replace them:

- **Structural patterns.** Match the documented shape of a credential
  (`AKIA` + 16 uppercase chars) rather than a nearby English word.
- **Entropy.** Each rule captures the secret itself in group 1, so Shannon
  entropy is measured on the credential alone, not on surrounding boilerplate.
- **Placeholder rejection.** `AKIAIOSFODNN7EXAMPLE`, `<your-token>`,
  `${API_KEY}`, `xxxxxxxx` and friends.
- **Code-reference rejection.** Applied only to rules that match on a variable
  *name* (`API_TOKEN = ...`): a value that is a qualified identifier or a
  function call is code, not a credential. This alone removed 3 of the 4
  remaining false positives.

Findings that overlap are collapsed — a Supabase service key is also a valid
JWT, and reporting both is the same secret counted twice. The more specific
rule wins.

## Notable behaviour

- **Secrets are redacted by default**, in every output format including the
  context snippet. A scan report is otherwise itself a secret-bearing artifact
  that ends up in CI logs and tickets. `--show-secrets` opts out.
- **Minified files still get scanned.** Over-long lines are split into
  overlapping windows rather than skipped, so a key embedded at column 320,004
  of a single-line bundle is still found, without the cost of matching the
  whole line at once.
- **Binaries are skipped** by extension, then by probing the first 8 KB for NUL
  bytes.
- **UTF-16 and UTF-32 files are scanned, not skipped.** Those encodings pad
  ASCII with NUL bytes, so the binary probe rejects them on sight — and
  PowerShell, .NET and registry exports emit UTF-16LE routinely. BOMs are
  recognised, and BOM-less UTF-16 is inferred from the alternation. That
  inference checks *both* sides of each byte pair: an ELF header is ~82% NUL
  with most of them on odd offsets, which imitates UTF-16LE perfectly, and only
  the requirement that the other side be printable text tells them apart.
- **Symlinks are not followed by default.** With `--follow-symlinks`,
  directories and files are tracked by `(device, inode)`, so a symlink cycle is
  detected rather than left to the kernel's `ELOOP` after ~40 levels, and a
  file reachable through several paths is reported once instead of once per
  path. The default path skips the extra `stat()` calls entirely.
- **`--git-tracked`** delegates to `git ls-files` instead of reimplementing
  `.gitignore` semantics.
- **Baselines** (`--write-baseline` / `--baseline`) suppress known findings by
  fingerprint so a scan can be adopted on an existing codebase.
- **Inline allowlisting** via `pragma: allowlist secret`.

## Exit codes

| code | meaning |
|---|---|
| 0 | no findings at or above `--fail-on` |
| 1 | findings reported |
| 2 | usage or I/O error — *the scan did not run* |

Keeping 1 and 2 distinct is what lets CI tell "this branch leaks a key" apart
from "the scanner was misconfigured".

## Rules

59 detectors across cloud (AWS, GCP, Azure, DigitalOcean, Cloudflare), VCS
(GitHub, GitLab), AI (OpenAI, Anthropic, Hugging Face), payments (Stripe,
Square, PayPal, Shopify), messaging (Slack, Discord, Telegram, Twilio,
SendGrid), packages (npm, PyPI, RubyGems, Docker Hub), infrastructure (Vault,
Terraform, Grafana, Datadog, Sentry), plus private keys, JWTs, database URIs
and generic assignments.

`--list-rules` prints them with severity, keywords and entropy thresholds.

Each rule carries its own structurally valid fake credential as a test vector.
`--self-test` asserts every rule matches its vector *and* that a clean-code
corpus produces zero findings, so a regex tightened for precision cannot
silently stop detecting anything. The examples are generated rather than
hand-written, because a hand-counted 82-character token is how test vectors
silently rot.

## Tests

`--self-test` needs no dependencies and covers the rules. The pytest suite
covers everything else — 305 tests, ~1.7 s.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install pytest
python -m pytest
```

It is organised by the property under test rather than by function: recall,
precision, redaction, robustness, discovery, overlap suppression, ruleset
integrity, entropy, determinism under multiprocessing, and the CLI contract.

### Breaking the circularity

`--self-test` matches each rule against `rule.example` — the very string the
regex was written for. That is circular: a pattern encoding the wrong idea of a
provider's format is wrong *together with* its example, and the check still
passes.

`tests/realistic_corpus.py` exists to break that loop. It composes credentials
from each provider's documented shape with random content from an unrelated
stream, and writes them into the file types credentials actually leak from —
`.env`, `Dockerfile`, `main.tf`, `.gitlab-ci.yml`, `.npmrc`, XML, Java
properties, shell scripts. A rule that silently only tolerates `key = "value"`
fails there rather than in production. `test_corpus_covers_every_rule` stops
the corpus falling behind the ruleset.

The irreducible limit: those shapes come from documentation, not live
credentials. If a shape is wrong here it is probably wrong in the rule too.
Entries that could not be confirmed are marked `UNVERIFIED` in that module.

Several tests exist because the behaviour they pin down was once wrong:

- `test_symlink_same_file_reported_once` — one secret reachable through a file,
  a symlink to it and a symlink to its directory was reported three times.
- `test_symlink_cycle_terminates` — a directory cycle used to recurse until the
  kernel raised `ELOOP` at ~40 levels.
- `test_real_credentials_are_not_mistaken_for_placeholders` — the low-variety
  heuristic scaled with length, so a 146-character hex token looked like
  padding and was dropped.
- `test_oversized_file_is_skipped` — with a `--max-file-size` below the 8 KB
  binary probe, the follow-up read length went negative and raised, filing an
  oversized file under "unreadable".
- `test_overlapping_windows_do_not_double_report` — scan windows overlap by
  design, so the same secret can match twice and must be collapsed.
- `test_encoding_variants[utf-16-le]` — UTF-16 files were classified as binary
  and never scanned.
- `test_elf_header_is_not_mistaken_for_utf16` — the first fix for the above
  misread every ELF binary as UTF-16 text.
- `test_credential_starting_with_punctuation_is_not_dropped` — the placeholder
  filter rejected any value starting with `$`, `%`, `(`, `[` or `<`, on the
  theory that it was template syntax, silently discarding strong passwords.
- `test_email_address_is_not_a_password` — `passwd="anonymous@domain.org"`, the
  anonymous-FTP convention, was reported as a hardcoded password.

Everything from `test_overlapping_windows_do_not_double_report` onward was
found by the test suite or the realistic corpus, not by hand testing.

`test_no_format_leaks_the_secret_by_default` is the one to keep if you keep
only one: it greps every output format for the raw credential.

## Ideas not implemented

- Scanning git history (`git log -p`) — secrets survive deletion in commits.
- Live credential validation, as TruffleHog does. Deliberately omitted: it
  means sending discovered credentials to third-party APIs.
