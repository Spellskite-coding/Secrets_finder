# secrets-finder

A fast, low-false-positive scanner for hardcoded credentials in source code trees.
Single file, standard library only, Python 3.10+.

```bash
python3 secrets_finder.py .                       # scan the current tree
python3 secrets_finder.py . --git-tracked         # only files tracked by git
python3 secrets_finder.py . -f sarif -o out.sarif # GitHub Code Scanning
python3 secrets_finder.py --self-test             # verify the 57 rules
```

## Measured results

Benchmark run on `/usr/lib/python3.13` — 627 text files, 11.2 MB,
303,452 lines — on 8 cores. Times are the minimum of 5 warm-cache runs,
the three measured consecutively.

| | rules | time | speedup | results |
|---|---|---|---|---|
| naive line×pattern loop | 11 | 18.55 s | — | **348** (nearly all wrong) |
| secrets-finder `-j 1` | 59 | 5.08 s | 3.7× | 1 |
| secrets-finder `-j 8` | 59 | **1.31 s** | **14.1×** | **1** |

**14× faster while evaluating 5× more rules, and 348 results narrowed down to 1.**

Absolute times depend on machine load — a second run of the same benchmark
on an idle machine gave 7.94 s / 2.08 s / 0.57 s. The ratios matched within
2%, so it's the speedup that matters, not the seconds.

The one remaining result is `passwd='geheim$parole'` in a `urllib.request`
docstring — an actual literal password in the source code, inside example
documentation. One could argue this is a correct match rather than a false
positive; removing it would require per-language syntactic parsing of
comments, which the scanner deliberately doesn't attempt.

Recall is checked separately: a corpus with one planted credential per
rule scores **59/59**, with no duplicate reported.

### On other real-world trees

| tree | results | assessment |
|---|---|---|
| `/usr/lib/python3.13` | 1 | a literal password in a docstring |
| `/usr/share/doc` | 13 | 10 are genuine PEM key files (OpenVPN/aiohttp example keys) |
| `/etc` | 1 | a PEM header inside an ImageMagick MIME magic pattern |

The `/etc` result could be eliminated by anchoring the private-key pattern
to the start of a line, and this was deliberately not done: in OpenVPN's
HTML documentation, that same header *is* at the start of a line, so
anchoring wouldn't fix the category, and it would lose keys embedded in
source code as string literals
(`KEY = "-----BEGIN RSA PRIVATE KEY-----\n..."`), which is a real leak. A
cheap triage dismissal beats a missed key.

## Why it's fast

Profiling the naive implementation showed that 83% of runtime was spent in
a single call — pattern matching on every line. Three changes account for
that gap:

1. **Keyword pre-filtering.** Every rule declares cheap literal keywords
   (`akia`, `ghp_`, `private key`). A single combined regex rejects lines
   that can't match any rule; only the survivors — 1.4% of lines here —
   are tested against the small subset of rules whose keywords are
   actually present.

2. **No `re.IGNORECASE` on the hot path.** The case-insensitive fallback
   defeats the regex engine's literal scan. Lowercasing each line once
   and then matching a case-sensitive trigger is **7× faster**, and the
   lowercased string is then reused for the ignore pragma and candidate
   lookup.

3. **Multiprocessing, done properly.** Python's `re` module doesn't
   release the GIL, so the scan is genuinely CPU-bound and threads
   wouldn't help. Workers compile the ruleset once, in an initializer, so
   each task only passes a path string. Below 200 files, the pool costs
   more than it saves and the scan runs inline.

## Why it's quiet

The naive version's 348 results came from patterns unable to distinguish
a credential from ordinary text. Four filters replace that:

- **Structural patterns.** Match the documented shape of a credential
  (`AKIA` + 16 uppercase characters) rather than a nearby English word.
- **Entropy.** Every rule captures the secret itself in group 1, so
  Shannon entropy is measured on the credential alone, not on the
  surrounding text.
- **Placeholder rejection.** `AKIAIOSFODNN7EXAMPLE`, `<your-token>`,
  `${API_KEY}`, `xxxxxxxx` and the like.
- **Code-reference rejection.** Applied only to rules that match on a
  variable *name* (`API_TOKEN = ...`): a value that's a qualified
  identifier or a function call is code, not a secret credential. On its
  own, this rule eliminated 3 of the 4 remaining false positives.

Overlapping results are merged — a Supabase service key is also a valid
JWT, and reporting both would count the same secret twice. The more
specific rule wins.

## Notable behavior

- **Secrets are redacted by default**, across every output format
  including the context excerpt. A scan report is otherwise itself a
  secret-carrying artifact that ends up in CI logs and tickets.
  `--show-secrets` disables this behavior.
- **Minified files are still scanned.** Overly long lines are split into
  overlapping windows rather than skipped, so a key embedded at column
  320,004 of a single-line bundle is still found, without the cost of
  matching the entire line at once.
- **Binaries are skipped** by extension, then by probing the first 8 KB
  for NUL bytes.
- **UTF-16 and UTF-32 files are scanned, not skipped.** These encodings
  pad ASCII with NUL bytes, so the binary probe rejects them at first
  glance — and PowerShell, .NET and registry exports commonly emit
  UTF-16LE. BOMs are recognized, and BOM-less UTF-16 is inferred from
  alternation. This inference checks *both sides* of every byte pair: an
  ELF header is about 82% NUL, mostly at odd positions, which perfectly
  mimics UTF-16LE, and only requiring the other side to be printable text
  tells them apart.
- **Symlinks aren't followed by default.** With `--follow-symlinks`,
  directories and files are tracked by `(device, inode)`, so a symlink
  cycle is detected rather than left to the kernel's `ELOOP` after about
  40 levels, and a file reachable via multiple paths is reported once
  instead of once per path. The default path avoids extra `stat()` calls
  entirely.
- **`--git-tracked`** delegates to `git ls-files` rather than
  reimplementing `.gitignore` semantics.
- **Baselines** (`--write-baseline` / `--baseline`) suppress results known
  by fingerprint, which makes adopting a scan on an existing codebase
  practical.
- **Inline allowlisting** via `pragma: allowlist secret`.

## Exit codes

| code | meaning |
|---|---|
| 0 | no result at or above `--fail-on` |
| 1 | results reported |
| 2 | usage or I/O error — *the scan didn't run* |

Distinguishing 1 from 2 lets CI tell "this branch leaks a key" apart from
"the scanner was misconfigured".

## Rules

59 detectors covering cloud (AWS, GCP, Azure, DigitalOcean, Cloudflare),
VCS (GitHub, GitLab), AI (OpenAI, Anthropic, Hugging Face), payments
(Stripe, Square, PayPal, Shopify), messaging (Slack, Discord, Telegram,
Twilio, SendGrid), packages (npm, PyPI, RubyGems, Docker Hub),
infrastructure (Vault, Terraform, Grafana, Datadog, Sentry), as well as
private keys, JWTs, database URIs and generic assignments.

`--list-rules` displays them with their severity, keywords and entropy
thresholds.

Every rule carries its own structurally valid fake credential as a test
vector. `--self-test` verifies that every rule matches its vector *and*
that a clean code corpus produces no result, so that a regex tightened for
precision can't silently stop detecting anything. Examples are generated
rather than handwritten, since a hand-counted 82-character token is how a
test vector silently rots.

## Tests

`--self-test` requires no dependency and covers the rules. The pytest
suite covers everything else — 305 tests, ~1.7 s.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install pytest
python -m pytest
```

It's organized by property tested rather than by function: recall,
precision, redaction, robustness, discovery, overlap suppression, ruleset
integrity, entropy, multiprocessing determinism, and the CLI contract.

### Breaking the circularity

`--self-test` matches every rule against `rule.example` — the very string
the regex was written for. That's circular: a pattern encoding a wrong
idea of a provider's format is wrong *at the same time as* its example,
and the test still passes.

`tests/realistic_corpus.py` exists to break that loop. It composes
credentials from each provider's documented shape with random content from
an unrelated stream, and writes them into the file types credentials
actually leak from — `.env`, `Dockerfile`, `main.tf`, `.gitlab-ci.yml`,
`.npmrc`, XML, Java properties, shell scripts. A rule that silently only
tolerates `key = "value"` fails there instead of in production.
`test_corpus_covers_every_rule` keeps the corpus from falling behind the
ruleset.

The irreducible limitation: these shapes come from documentation, not from
real credentials in the wild. If a shape is wrong here, it's probably
wrong in the rule too. Entries that couldn't be confirmed are marked
`UNVERIFIED` in this module.

Several tests exist because the behavior they lock in used to be wrong:

- `test_symlink_same_file_reported_once` — a secret reachable via a file,
  a symlink to it, and a symlink to its directory was reported three
  times.
- `test_symlink_cycle_terminates` — a directory cycle used to cause
  recursion until the kernel raised `ELOOP` at around 40 levels.
- `test_real_credentials_are_not_mistaken_for_placeholders` — the
  low-variety heuristic scaled with length, so a 146-character hex token
  looked like padding and was discarded.
- `test_oversized_file_is_skipped` — with a `--max-file-size` smaller than
  the 8 KB binary probe, the next read length went negative and raised an
  error, classifying an oversized file as "unreadable".
- `test_overlapping_windows_do_not_double_report` — scan windows overlap
  by design, so the same secret can match twice and must be merged.
- `test_encoding_variants[utf-16-le]` — UTF-16 files used to be classified
  as binary and never scanned.
- `test_elf_header_is_not_mistaken_for_utf16` — the first fix for the
  point above made every ELF binary get read as UTF-16 text.
- `test_credential_starting_with_punctuation_is_not_dropped` — the
  placeholder filter rejected any value starting with `$`, `%`, `(`, `[`
  or `<`, on the assumption it was template syntax, silently discarding
  strong passwords.
- `test_email_address_is_not_a_password` — `passwd="anonymous@domain.org"`,
  the anonymous-FTP convention, was reported as a hardcoded password.

Everything after `test_overlapping_windows_do_not_double_report` was
discovered by the test suite or the realistic corpus, not by manual
testing.

`test_no_format_leaks_the_secret_by_default` is the one to keep if you
only keep one: it greps every output format for the raw credential.

## Ideas not implemented

- Scanning git history (`git log -p`) — secrets survive deletion in
  commits.
- Live credential validation, the way TruffleHog does. Deliberately
  omitted: it would mean sending discovered credentials to third-party
  APIs.
