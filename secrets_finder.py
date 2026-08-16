#!/usr/bin/env python3
"""
secrets-finder — a fast, low-false-positive secret scanner.

Design notes
------------
The scanner is built around three ideas that keep it both fast and quiet:

1. **Keyword pre-filtering.** Running N regexes against every line of every file
   is what makes naive scanners slow. Instead, every rule declares cheap literal
   keywords ("akia", "ghp_", "private key", ...). A single combined regex rejects
   the ~99% of lines that cannot possibly match any rule, and only surviving
   lines are tested against the small subset of rules whose keywords are present.

2. **Capture the secret, not the line.** Each rule captures the credential
   itself in group 1. That makes it possible to (a) measure Shannon entropy on
   the secret alone rather than on surrounding boilerplate, (b) redact it in the
   report, and (c) fingerprint it for baselining.

3. **Structural patterns over generic ones.** Most credentials have a documented
   shape (`AKIA` + 16 uppercase chars, `ghp_` + 36 chars, ...). Matching that
   shape gives near-zero false positives. Generic `key = "..."` rules exist too,
   but they are gated behind entropy and placeholder filters.

Exit codes: 0 = clean, 1 = findings at/above --fail-on, 2 = error.
"""

from __future__ import annotations

import argparse
import codecs
import concurrent.futures as cf
import csv
import hashlib
import json
import math
import os
import random
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Iterable, Iterator, Sequence

__version__ = "2.0.0"

# --------------------------------------------------------------------------- #
# Severity
# --------------------------------------------------------------------------- #


class Severity(IntEnum):
    LOW = 10
    MEDIUM = 20
    HIGH = 30
    CRITICAL = 40

    @property
    def label(self) -> str:
        return self.name

    @classmethod
    def parse(cls, value: str) -> "Severity":
        return cls[value.upper()]


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

_ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_HEX = "0123456789abcdef"
_B64 = _ALNUM + "-_"


def _tok(n: int, alphabet: str = _ALNUM, seed: int = 7) -> str:
    """Deterministic pseudo-random token, used to build rule test vectors.

    Hand-writing an 82-character example and counting the characters by eye is
    how test vectors silently rot; generating them guarantees the self-test
    actually exercises the length constraints in the pattern.
    """
    rnd = random.Random(seed)
    return "".join(rnd.choice(alphabet) for _ in range(n))


@dataclass(frozen=True)
class Rule:
    """A single detector.

    Attributes
    ----------
    id:          stable machine-readable identifier (used in SARIF and baselines)
    name:        human-readable description
    pattern:     regex with at most one capturing group, which must isolate the
                 credential itself. If the pattern has no group, the whole match
                 is treated as the secret.
    severity:    triage priority
    keywords:    lowercase literals; a line must contain at least one of them
                 before this rule is evaluated. This is the pre-filter and it is
                 mandatory — a rule without keywords would run on every line.
    min_entropy: minimum Shannon entropy (bits/char) of the captured secret.
                 0.0 for structural patterns that are already unambiguous.
    example:     a structurally valid, entirely fake credential used by --self-test.
    generic:     True for keyword-driven rules that match on naming convention
                 rather than on credential structure. These get extra scrutiny
                 (see looks_like_non_secret) because "TOKEN = something" is
                 overwhelmingly more often code than a credential.
    """

    id: str
    name: str
    pattern: str
    severity: Severity
    keywords: tuple[str, ...]
    example: str
    min_entropy: float = 0.0
    flags: int = re.IGNORECASE
    generic: bool = False


def _r(
    id: str,
    name: str,
    pattern: str,
    severity: Severity,
    keywords: Sequence[str],
    example: str,
    min_entropy: float = 0.0,
    flags: int = re.IGNORECASE,
    generic: bool = False,
) -> Rule:
    return Rule(
        id, name, pattern, severity, tuple(k.lower() for k in keywords), example,
        min_entropy, flags, generic,
    )


RULES: list[Rule] = [
    # ---------------------------------------------------------------- cloud --
    _r(
        "aws-access-key-id",
        "AWS Access Key ID",
        r"\b((?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})\b",
        Severity.HIGH,
        ["akia", "asia", "abia", "acca", "a3t"],
        "AKIA" + _tok(16, _UPPER, seed=1),
        flags=0,  # AWS key IDs are uppercase by definition; matching case-insensitively
        # would match ordinary lowercase words such as "akia..." in prose.
    ),
    _r(
        "aws-secret-access-key",
        "AWS Secret Access Key",
        r"aws[a-z0-9_\-. ]{0,25}(?:secret|private)[a-z0-9_\-. ]{0,25}[:=]\s*[\"']?([A-Za-z0-9/+=]{40})\b",
        Severity.CRITICAL,
        ["aws"],
        'aws_secret_access_key = "' + _tok(40, _ALNUM + "/+", seed=2) + '"',
        min_entropy=3.5,
    ),
    _r(
        "aws-session-token",
        "AWS Session Token",
        r"aws[a-z0-9_\-. ]{0,20}session[_\-. ]?token[a-z0-9_\-. ]{0,10}[:=]\s*[\"']?([A-Za-z0-9/+=]{100,})",
        Severity.HIGH,
        ["session_token", "sessiontoken", "session token"],
        "aws_session_token=" + _tok(180, _ALNUM + "/+", seed=3),
        min_entropy=3.5,
    ),
    _r(
        "gcp-api-key",
        "Google Cloud / Firebase API Key",
        r"\b(AIza[0-9A-Za-z_\-]{35})\b",
        Severity.MEDIUM,
        ["aiza"],
        "AIza" + _tok(35, _B64, seed=4),
        flags=0,
    ),
    _r(
        "gcp-oauth-client-secret",
        "Google OAuth Client Secret",
        r"\b(GOCSPX-[a-zA-Z0-9_\-]{28})\b",
        Severity.HIGH,
        ["gocspx-"],
        "GOCSPX-" + _tok(28, _B64, seed=5),
        flags=0,
    ),
    _r(
        "gcp-service-account",
        "GCP Service Account Key File",
        r"(\"type\"\s*:\s*\"service_account\")",
        Severity.CRITICAL,
        ["service_account"],
        '"type": "service_account",',
    ),
    _r(
        "azure-storage-key",
        "Azure Storage Account Key",
        r"AccountKey\s*=\s*([A-Za-z0-9/+]{86}==)",
        Severity.CRITICAL,
        ["accountkey"],
        "AccountKey=" + _tok(86, _ALNUM + "/+", seed=6) + "==",
        min_entropy=3.5,
    ),
    _r(
        "digitalocean-token",
        "DigitalOcean Personal Access Token",
        r"\b(dop_v1_[a-f0-9]{64})\b",
        Severity.HIGH,
        ["dop_v1_"],
        "dop_v1_" + _tok(64, _HEX, seed=8),
    ),
    _r(
        "heroku-api-key",
        "Heroku API Key",
        r"heroku[a-z0-9_\-. ]{0,20}(?:api|key|token)[a-z0-9_\-. ]{0,10}[:=]\s*[\"']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b",
        Severity.HIGH,
        ["heroku"],
        'heroku_api_key = "01234567-89ab-cdef-0123-456789abcdef"',
    ),
    _r(
        # Named for what it actually is. The `v1.0-<24hex>-<146hex>` shape is
        # Cloudflare's Origin CA key, not an API token — the two are different
        # credentials with different blast radius, and calling this one an API
        # token sent triagers looking for the wrong thing to revoke.
        "cloudflare-origin-ca-key",
        "Cloudflare Origin CA Key",
        r"\b(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})\b",
        Severity.HIGH,
        ["v1.0-"],
        "v1.0-" + _tok(24, _HEX, seed=9) + "-" + _tok(146, _HEX, seed=10),
    ),
    _r(
        # A real Cloudflare API token is 40 unprefixed [A-Za-z0-9_-] characters,
        # indistinguishable from any other slug, so it can only be found via the
        # surrounding variable name.
        "cloudflare-api-token",
        "Cloudflare API Token",
        r"cloudflare[a-z0-9_\-. ]{0,25}(?:api[_\-. ]?)?token[a-z0-9_\-. ]{0,10}[:=]\s*[\"']?([A-Za-z0-9_\-]{40})\b",
        Severity.HIGH,
        ["cloudflare"],
        'cloudflare_api_token = "' + _tok(40, _B64, seed=67) + '"',
        min_entropy=3.0,
    ),
    _r(
        "cloudflare-global-api-key",
        "Cloudflare Global API Key",
        r"cloudflare[a-z0-9_\-. ]{0,25}(?:global[_\-. ]?)?(?:api[_\-. ]?)?key[a-z0-9_\-. ]{0,10}[:=]\s*[\"']?([a-f0-9]{37})\b",
        Severity.CRITICAL,
        ["cloudflare"],
        'cloudflare_global_api_key = "' + _tok(37, _HEX, seed=68) + '"',
        min_entropy=3.0,
    ),
    # ------------------------------------------------------------------ vcs --
    _r(
        "github-pat",
        "GitHub Personal Access Token",
        r"\b(gh[pousr]_[A-Za-z0-9]{36})\b",
        Severity.CRITICAL,
        ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        "ghp_" + _tok(36, _ALNUM, seed=11),
        flags=0,
    ),
    _r(
        "github-fine-grained-pat",
        "GitHub Fine-Grained PAT",
        r"\b(github_pat_[0-9a-zA-Z_]{82})\b",
        Severity.CRITICAL,
        ["github_pat_"],
        "github_pat_" + _tok(82, _ALNUM + "_", seed=12),
    ),
    _r(
        "gitlab-pat",
        "GitLab Personal Access Token",
        r"\b(glpat-[0-9a-zA-Z_\-]{20,})\b",
        Severity.CRITICAL,
        ["glpat-"],
        "glpat-" + _tok(20, _B64, seed=13),
    ),
    _r(
        "gitlab-runner-token",
        "GitLab Runner Registration Token",
        r"\b(GR1348941[0-9a-zA-Z_\-]{20})\b",
        Severity.HIGH,
        ["gr1348941"],
        "GR1348941" + _tok(20, _B64, seed=14),
    ),
    # ---------------------------------------------------------------- ai/ml --
    _r(
        "openai-legacy-key",
        "OpenAI API Key (legacy)",
        r"\b(sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})\b",
        Severity.HIGH,
        ["t3blbkfj"],
        "sk-" + _tok(20, _ALNUM, seed=15) + "T3BlbkFJ" + _tok(20, _ALNUM, seed=16),
    ),
    _r(
        "openai-project-key",
        "OpenAI API Key (project)",
        r"\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,})\b",
        Severity.HIGH,
        ["sk-proj-", "sk-svcacct-", "sk-admin-"],
        "sk-proj-" + _tok(74, _B64, seed=17),
    ),
    _r(
        "anthropic-key",
        "Anthropic API Key",
        r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,})\b",
        Severity.HIGH,
        ["sk-ant-"],
        "sk-ant-api03-" + _tok(95, _B64, seed=18),
    ),
    _r(
        "huggingface-token",
        "Hugging Face Access Token",
        r"\b(hf_[A-Za-z0-9]{34})\b",
        Severity.HIGH,
        ["hf_"],
        "hf_" + _tok(34, _ALNUM, seed=19),
    ),
    # ------------------------------------------------------------- payments --
    _r(
        "stripe-secret-key",
        "Stripe Secret Key",
        r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,99})\b",
        Severity.CRITICAL,
        ["sk_live_", "rk_live_"],
        "sk_live_" + _tok(24, _ALNUM, seed=20),
    ),
    _r(
        "stripe-test-key",
        "Stripe Test Key",
        r"\b((?:sk|rk)_test_[0-9a-zA-Z]{24,99})\b",
        Severity.LOW,
        ["sk_test_", "rk_test_"],
        "sk_test_" + _tok(24, _ALNUM, seed=21),
    ),
    _r(
        "square-token",
        "Square Access Token",
        r"\b((?:sq0atp|sq0csp)-[0-9A-Za-z_\-]{22,43})\b",
        Severity.HIGH,
        ["sq0atp-", "sq0csp-"],
        "sq0atp-" + _tok(22, _B64, seed=22),
    ),
    _r(
        "paypal-braintree-token",
        "PayPal / Braintree Access Token",
        r"\b(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})\b",
        Severity.CRITICAL,
        ["access_token$production$"],
        "access_token$production$" + _tok(16, _HEX, seed=23) + "$" + _tok(32, _HEX, seed=24),
    ),
    _r(
        "shopify-token",
        "Shopify Access Token",
        r"\b(shp(?:ss|at|ca|pa)_[a-fA-F0-9]{32})\b",
        Severity.HIGH,
        ["shpss_", "shpat_", "shpca_", "shppa_"],
        "shpat_" + _tok(32, _HEX, seed=25),
    ),
    # ------------------------------------------------------------- messaging -
    _r(
        "slack-token",
        "Slack Token",
        r"\b(xox[baprse]-[0-9A-Za-z\-]{10,72})\b",
        Severity.HIGH,
        ["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", "xoxe-"],
        "xoxb-" + _tok(12, "0123456789", seed=26) + "-" + _tok(24, _ALNUM, seed=27),
    ),
    _r(
        "slack-webhook",
        "Slack Incoming Webhook",
        r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{20,})",
        Severity.MEDIUM,
        ["hooks.slack.com"],
        "https://hooks.slack.com/services/T"
        + _tok(10, _UPPER, seed=28)
        + "/B"
        + _tok(10, _UPPER, seed=29)
        + "/"
        + _tok(24, _ALNUM, seed=30),
    ),
    _r(
        "discord-bot-token",
        "Discord Bot Token",
        r"\b([MNO][a-zA-Z0-9_\-]{23,25}\.[a-zA-Z0-9_\-]{6}\.[a-zA-Z0-9_\-]{27,38})\b",
        Severity.HIGH,
        ["discord", "bot "],
        "discord token: M"
        + _tok(23, _B64, seed=31)
        + "."
        + _tok(6, _B64, seed=32)
        + "."
        + _tok(27, _B64, seed=33),
    ),
    _r(
        "discord-webhook",
        "Discord Webhook",
        r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_\-]{60,})",
        Severity.MEDIUM,
        ["discord.com/api/webhooks", "discordapp.com/api/webhooks"],
        "https://discord.com/api/webhooks/"
        + _tok(18, "0123456789", seed=34)
        + "/"
        + _tok(68, _B64, seed=35),
    ),
    _r(
        "telegram-bot-token",
        "Telegram Bot Token",
        r"\b([0-9]{8,10}:AA[0-9A-Za-z_\-]{32,33})\b",
        Severity.HIGH,
        [":aa"],
        _tok(9, "0123456789", seed=36) + ":AA" + _tok(33, _B64, seed=37),
    ),
    _r(
        "twilio-api-key",
        "Twilio API Key SID",
        r"\b(SK[0-9a-fA-F]{32})\b",
        Severity.HIGH,
        ["sk"],
        "SK" + _tok(32, _HEX, seed=38),
        flags=0,
    ),
    _r(
        "sendgrid-key",
        "SendGrid API Key",
        r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b",
        Severity.HIGH,
        ["sg."],
        "SG." + _tok(22, _B64, seed=39) + "." + _tok(43, _B64, seed=40),
    ),
    _r(
        "mailgun-key",
        "Mailgun API Key",
        r"\b(key-[0-9a-f]{32})\b",
        Severity.HIGH,
        ["key-"],
        "key-" + _tok(32, _HEX, seed=41),
    ),
    _r(
        "mailchimp-key",
        "Mailchimp API Key",
        r"\b([0-9a-f]{32}-us[0-9]{1,2})\b",
        Severity.HIGH,
        ["-us"],
        _tok(32, _HEX, seed=42) + "-us14",
    ),
    _r(
        "postmark-token",
        "Postmark Server Token",
        r"postmark[a-z0-9_\-. ]{0,20}token[a-z0-9_\-. ]{0,10}[:=]\s*[\"']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b",
        Severity.MEDIUM,
        ["postmark"],
        'postmark_server_token = "01234567-89ab-cdef-0123-456789abcdef"',
    ),
    # ------------------------------------------------------------- packages --
    _r(
        "npm-token",
        "npm Access Token",
        r"\b(npm_[A-Za-z0-9]{36})\b",
        Severity.HIGH,
        ["npm_"],
        "npm_" + _tok(36, _ALNUM, seed=43),
    ),
    _r(
        "pypi-token",
        "PyPI Upload Token",
        r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})\b",
        Severity.HIGH,
        ["pypi-"],
        "pypi-AgEIcHlwaS5vcmc" + _tok(60, _B64, seed=44),
    ),
    _r(
        "rubygems-key",
        "RubyGems API Key",
        r"\b(rubygems_[a-f0-9]{48})\b",
        Severity.HIGH,
        ["rubygems_"],
        "rubygems_" + _tok(48, _HEX, seed=45),
    ),
    _r(
        "docker-hub-pat",
        "Docker Hub Personal Access Token",
        r"\b(dckr_pat_[A-Za-z0-9_\-]{27})\b",
        Severity.HIGH,
        ["dckr_pat_"],
        "dckr_pat_" + _tok(27, _B64, seed=46),
    ),
    # -------------------------------------------------------------- devtools -
    _r(
        "sentry-dsn",
        "Sentry DSN with Secret",
        r"(https://[0-9a-f]{32}:[0-9a-f]{32}@[a-z0-9.\-]+/[0-9]+)",
        Severity.MEDIUM,
        ["sentry.io", "@o", "ingest."],
        "https://" + _tok(32, _HEX, seed=47) + ":" + _tok(32, _HEX, seed=48) + "@sentry.io/12345",
    ),
    _r(
        "datadog-key",
        "Datadog API Key",
        r"(?:datadog|dd)[a-z0-9_\-. ]{0,20}(?:api|app)[_\-. ]?key[a-z0-9_\-. ]{0,10}[:=]\s*[\"']?([a-f0-9]{32})\b",
        Severity.HIGH,
        ["datadog", "dd_api", "dd_app"],
        'datadog_api_key = "' + _tok(32, _HEX, seed=49) + '"',
    ),
    _r(
        "algolia-admin-key",
        "Algolia Admin API Key",
        r"algolia[a-z0-9_\-. ]{0,20}(?:admin|api)[_\-. ]?key[a-z0-9_\-. ]{0,10}[:=]\s*[\"']?([a-f0-9]{32})\b",
        Severity.HIGH,
        ["algolia"],
        'algolia_admin_key = "' + _tok(32, _HEX, seed=50) + '"',
    ),
    _r(
        "atlassian-token",
        "Atlassian / Jira API Token",
        r"\b(ATATT3[A-Za-z0-9_\-=]{180,})\b",
        Severity.HIGH,
        ["atatt3"],
        "ATATT3" + _tok(190, _B64, seed=51),
    ),
    _r(
        "notion-token",
        "Notion Integration Token",
        r"\b((?:secret_|ntn_)[A-Za-z0-9]{40,50})\b",
        Severity.HIGH,
        ["secret_", "ntn_"],
        "ntn_" + _tok(46, _ALNUM, seed=52),
    ),
    _r(
        "linear-key",
        "Linear API Key",
        r"\b(lin_api_[A-Za-z0-9]{40})\b",
        Severity.HIGH,
        ["lin_api_"],
        "lin_api_" + _tok(40, _ALNUM, seed=53),
    ),
    _r(
        "supabase-service-key",
        "Supabase Service Role Key",
        r"(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{0,400}service_role[A-Za-z0-9_\-]{0,400}\.[A-Za-z0-9_\-]{20,})",
        Severity.CRITICAL,
        ["service_role"],
        "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0service_roleX."
        + _tok(43, _B64, seed=54),
    ),
    _r(
        "vault-token",
        "HashiCorp Vault Token",
        r"\b((?:hvs|hvb|hvr|hvu)\.[A-Za-z0-9_\-]{24,})\b",
        Severity.CRITICAL,
        ["hvs.", "hvb.", "hvr.", "hvu."],
        "hvs." + _tok(90, _B64, seed=55),
    ),
    _r(
        "terraform-cloud-token",
        "Terraform Cloud API Token",
        r"\b([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,})\b",
        Severity.HIGH,
        [".atlasv1."],
        _tok(14, _ALNUM, seed=56) + ".atlasv1." + _tok(67, _B64, seed=57),
    ),
    _r(
        "grafana-token",
        "Grafana Service Account Token",
        r"\b((?:glc_|glsa_)[A-Za-z0-9_\-]{32,})\b",
        Severity.HIGH,
        ["glc_", "glsa_"],
        "glsa_" + _tok(40, _B64, seed=58),
    ),
    # ------------------------------------------------------------- generic ---
    _r(
        "private-key",
        "Private Key Block",
        r"(-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|SSH2 ENCRYPTED|ENCRYPTED)?\s*PRIVATE KEY(?:\s+BLOCK)?-----)",
        Severity.CRITICAL,
        ["private key"],
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    ),
    _r(
        "putty-private-key",
        "PuTTY Private Key",
        r"(PuTTY-User-Key-File-\d+\s*:)",
        Severity.CRITICAL,
        ["putty-user-key-file"],
        "PuTTY-User-Key-File-2: ssh-rsa",
    ),
    _r(
        "age-secret-key",
        "age Encryption Secret Key",
        r"\b(AGE-SECRET-KEY-1[0-9A-Z]{58})\b",
        Severity.CRITICAL,
        ["age-secret-key-1"],
        "AGE-SECRET-KEY-1" + _tok(58, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", seed=59),
        flags=0,
    ),
    _r(
        "jwt",
        "JSON Web Token",
        r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b",
        Severity.MEDIUM,
        ["eyj"],
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        + _tok(43, _B64, seed=60),
    ),
    _r(
        "db-connection-uri",
        "Database URI with Credentials",
        r"\b(?:mysql|mariadb|postgres(?:ql)?|mongodb(?:\+srv)?|redis[s]?|amqps?|mssql|clickhouse|ftp)://[^\s:@/]+:([^\s:@/]{3,})@[^\s/]+",
        Severity.CRITICAL,
        ["mysql://", "mariadb://", "postgres://", "postgresql://", "mongodb://",
         "mongodb+srv://", "redis://", "rediss://", "amqp://", "amqps://",
         "mssql://", "clickhouse://", "ftp://"],
        "postgres://admin:" + _tok(20, _ALNUM, seed=61) + "@db.internal:5432/prod",
        min_entropy=2.0,
    ),
    _r(
        "url-basic-auth",
        "URL with Embedded Basic-Auth Password",
        r"\bhttps?://[^\s:@/]+:([^\s:@/]{6,})@[^\s/]+",
        Severity.HIGH,
        ["://"],
        "https://svc:" + _tok(24, _ALNUM, seed=62) + "@api.internal/v1",
        min_entropy=3.0,
        generic=True,
    ),
    _r(
        "authorization-header",
        "Hardcoded Authorization Header",
        r"authorization[\"']?\s*[:=]\s*[\"']?(?:bearer|token|basic)\s+([A-Za-z0-9._~+/=\-]{20,})",
        Severity.HIGH,
        ["authorization"],
        'Authorization: Bearer ' + _tok(48, _B64, seed=63),
        min_entropy=3.0,
        generic=True,
    ),
    _r(
        "generic-secret-assignment",
        "Generic Secret Assignment",
        r"\b[a-z0-9_\-]{0,25}(?:api[_\-]?key|secret|token|passwd|password|client[_\-]?secret|access[_\-]?key|auth[_\-]?key)s?[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-.+/=~]{16,120})[\"']",
        Severity.MEDIUM,
        ["api_key", "apikey", "api-key", "secret", "token", "passwd", "password", "access_key", "auth_key"],
        'client_secret = "' + _tok(40, _ALNUM, seed=64) + '"',
        min_entropy=3.2,
        generic=True,
    ),
    _r(
        "generic-env-assignment",
        "Secret in Environment Variable",
        # The value charset deliberately excludes brackets, commas and semicolons:
        # without that, `HEADER_TOKEN_RE = re.compile(r"...")` matches, and code
        # assigned to a TOKEN-shaped name is the single largest FP source here.
        r"^\s*(?:export\s+)?[A-Z][A-Z0-9_]{0,40}(?:API_KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIALS?)[A-Z0-9_]{0,20}\s*=\s*[\"']?([A-Za-z0-9_\-.+/=~!@$%^&]{12,120})",
        Severity.MEDIUM,
        ["api_key", "secret", "token", "password", "passwd", "credential"],
        "export DATABASE_PASSWORD=" + _tok(32, _ALNUM, seed=65),
        min_entropy=3.0,
        flags=0,
        generic=True,
    ),
    _r(
        "generic-password-literal",
        "Hardcoded Password Literal",
        r"\b(?:password|passwd|pwd)[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,64})[\"']",
        Severity.MEDIUM,
        ["password", "passwd", "pwd"],
        'password = "' + _tok(18, _ALNUM + "!@#$%", seed=66) + '"',
        min_entropy=2.8,
        generic=True,
    ),
]


# --------------------------------------------------------------------------- #
# Rule compilation & validation
# --------------------------------------------------------------------------- #


_RULE_BY_ID: dict[str, Rule] = {r.id: r for r in RULES}


class CompiledRule:
    __slots__ = ("rule", "regex")

    def __init__(self, rule: Rule) -> None:
        self.rule = rule
        self.regex = re.compile(rule.pattern, rule.flags)


class RuleSet:
    """Compiled rules plus the keyword index that drives the pre-filter."""

    def __init__(self, rules: Sequence[Rule]) -> None:
        self.rules = list(rules)
        self.compiled = [CompiledRule(r) for r in self.rules]
        self._validate()

        # keyword -> indices of rules that declare it
        self.keyword_index: dict[str, list[int]] = {}
        for i, r in enumerate(self.rules):
            for kw in r.keywords:
                self.keyword_index.setdefault(kw, []).append(i)

        # One combined regex used purely as a fast rejector, matched against an
        # already-lowercased line. Compiling it with re.IGNORECASE instead is
        # ~7x slower: case folding defeats the engine's literal scan, and this
        # regex sees every byte of every file, so it dominates the whole run.
        keywords = sorted(self.keyword_index, key=len, reverse=True)
        self.trigger = re.compile("|".join(re.escape(k) for k in keywords))

    def _validate(self) -> None:
        seen: set[str] = set()
        for cr in self.compiled:
            r = cr.rule
            if r.id in seen:
                raise ValueError(f"duplicate rule id: {r.id}")
            seen.add(r.id)
            if cr.regex.groups > 1:
                raise ValueError(
                    f"rule {r.id!r} has {cr.regex.groups} capturing groups; "
                    "exactly one (the secret) is allowed — use (?:...) elsewhere"
                )
            if not r.keywords:
                raise ValueError(f"rule {r.id!r} declares no keywords (pre-filter would be bypassed)")

    def by_id(self, rule_id: str) -> Rule | None:  # noqa: D102
        for r in self.rules:
            if r.id == rule_id:
                return r
        return None

    def candidates(self, lowered_line: str) -> set[int]:
        """Rules whose keywords actually occur in the line.

        Called only for lines that already passed the trigger regex, so the
        per-keyword substring scan here runs on a small minority of input.
        """
        idx: set[int] = set()
        for kw, rule_ids in self.keyword_index.items():
            if kw in lowered_line:
                idx.update(rule_ids)
        return idx


# --------------------------------------------------------------------------- #
# Heuristics: entropy, placeholders, redaction
# --------------------------------------------------------------------------- #


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


# Strong markers only. Weak markers such as a bare "test" would suppress real
# credentials that happen to contain the substring.
PLACEHOLDER_TOKENS = (
    # "your" and "_here" cover the whole your_api_key_here / yourToken family in
    # one entry each. Enumerating the variants missed combinations such as
    # "your_api_key_here_please"; the odds of a random 40-character credential
    # containing either substring are around one in a million.
    "example", "placeholder", "changeme", "change_me", "your", "_here", "-here",
    "redacted", "insert_", "dummy", "notreal", "xxxxxxxx", "aaaaaaaa",
    "1234567890abcdef1234", "deadbeef", "s3cr3t", "supersecret", "mysecret",
    "fakefake", "sample_", "replace_me", "todo",
)

# Match actual template syntax, never a bare leading punctuation character.
# An earlier `^[<{$%(\[]` alternative discarded every credential starting with
# $, %, (, [ or < — which is a large share of strong passwords, silently turned
# into false negatives.
_TEMPLATE_RE = re.compile(
    r"""
      \$\{            # ${VAR}
    | \{\{            # {{ var }}
    | %\(             # %(name)s
    | <%              # <% erb %>
    | ^<[^>]*>$       # <your-token>
    | ^__[A-Z_]+__$   # __PLACEHOLDER__
    """,
    re.VERBOSE,
)


def looks_like_placeholder(secret: str) -> bool:
    """Reject obvious documentation/template values."""
    low = secret.lower()
    if any(tok in low for tok in PLACEHOLDER_TOKENS):
        return True
    if _TEMPLATE_RE.search(secret):
        return True
    # Very low character variety: "xxxxxxxxxxxx", "000000000000", "abababab".
    # The threshold is a small constant, not a fraction of the length: a long
    # hex token legitimately draws on only 16 distinct characters, so scaling
    # this with length silently discards real credentials.
    if len(set(low)) <= 4:
        return True
    return False


# `module.CONSTANT`, `obj.attr` — a qualified name, never a credential.
_DOTTED_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+")
# `re.compile(`, `os.getenv(` — the assigned value is a call, not a literal.
_CALL_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*\s*\(")
# An email address is an identifier, not a secret. `passwd="anonymous@host.org"`
# is the anonymous-FTP convention, and it is what this catches in practice.
_EMAIL_RE = re.compile(r"[^@\s]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")


def looks_like_non_secret(secret: str) -> bool:
    """Reject values that are plainly not credentials: source code or identifiers.

    Only applied to rules flagged `generic`: those match on a variable *name*
    ("...TOKEN = ..."), so whatever follows the `=` is usually an expression.
    Structural rules must not use this filter — a SendGrid key such as
    `SG.abc.def` is itself shaped like a dotted identifier.
    """
    return bool(
        _DOTTED_IDENT_RE.fullmatch(secret)
        or _CALL_RE.match(secret)
        or _EMAIL_RE.fullmatch(secret)
    )


IGNORE_MARKERS = ("pragma: allowlist secret", "secretsfinder:ignore", "noqa: secret")


def has_inline_ignore(lowered_line: str) -> bool:
    """Check for an allowlist pragma. Expects an already-lowercased line."""
    return any(marker in lowered_line for marker in IGNORE_MARKERS)


def redact(secret: str) -> str:
    n = len(secret)
    if n <= 8:
        return "*" * n
    return f"{secret[:4]}{'*' * min(n - 8, 16)}{secret[-4:]}"


def fingerprint(rule_id: str, path: str, secret: str) -> str:
    h = hashlib.sha256()
    h.update(f"{rule_id}\0{path}\0{secret}".encode("utf-8", "replace"))
    return h.hexdigest()[:16]


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: int
    path: str
    line: int
    column: int
    secret: str
    entropy: float
    preview: str
    fingerprint: str

    def redacted_secret(self) -> str:
        return redact(self.secret)

    def to_dict(self, show_secrets: bool = False) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": Severity(self.severity).label,
            "file": self.path,
            "line": self.line,
            "column": self.column,
            "secret": self.secret if show_secrets else self.redacted_secret(),
            "entropy": round(self.entropy, 3),
            "preview": self.preview,
            "fingerprint": self.fingerprint,
        }


def suppress_overlaps(findings: Sequence[Finding]) -> list[Finding]:
    """Collapse several rules matching the same credential into one finding.

    A Supabase service key is also a valid JWT; a Datadog key assignment also
    matches the generic `*_key = "..."` rule. Reporting both is not extra
    signal, it is the same secret counted twice. When two matches on a line
    overlap, the more specific rule wins: structural beats generic, then higher
    severity, then the longer match.
    """
    def rank(f: Finding) -> tuple:
        rule = _RULE_BY_ID.get(f.rule_id)
        specific = 0 if (rule and rule.generic) else 1
        return (specific, f.severity, len(f.secret))

    kept: list[Finding] = []
    by_line: dict[tuple[str, int], list[Finding]] = {}
    for f in findings:
        by_line.setdefault((f.path, f.line), []).append(f)

    for group in by_line.values():
        # Best-first, so a kept finding always outranks anything it absorbs.
        winners: list[Finding] = []
        for f in sorted(group, key=rank, reverse=True):
            f_end = f.column + len(f.secret)
            if any(f.column < w.column + len(w.secret) and w.column < f_end for w in winners):
                continue
            winners.append(f)
        kept.extend(winners)
    return kept


@dataclass
class Stats:
    files_scanned: int = 0
    files_skipped_binary: int = 0
    files_skipped_large: int = 0
    files_skipped_ext: int = 0
    files_unreadable: int = 0
    bytes_scanned: int = 0
    lines_scanned: int = 0
    lines_triggered: int = 0

    def merge(self, other: "Stats") -> None:
        for f in self.__dataclass_fields__:
            setattr(self, f, getattr(self, f) + getattr(other, f))


# --------------------------------------------------------------------------- #
# Scan configuration
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ScanConfig:
    max_file_size: int = 10 * 1024 * 1024
    max_line_length: int = 4096
    line_overlap: int = 512
    min_entropy_override: float | None = None
    filter_placeholders: bool = True
    respect_inline_ignore: bool = True
    entropy_scan: bool = False
    entropy_scan_threshold: float = 4.5
    preview_width: int = 160


DEFAULT_EXCLUDE_DIRS = frozenset({
    ".git", ".hg", ".svn", ".bzr", "node_modules", "bower_components", "vendor",
    "venv", ".venv", "env", ".env.d", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", ".nox", "dist", "build", "target", ".next", ".nuxt",
    ".gradle", ".idea", ".vscode", "site-packages", ".terraform", ".serverless",
    "coverage", ".cache", "bin", "obj",
})

# Extensions that are either binary or pure noise. Skipping them by name is far
# cheaper than opening the file and probing for NUL bytes.
DEFAULT_EXCLUDE_EXTS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff", ".svg",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".flac", ".wav", ".ogg", ".webm",
    ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".tgz", ".jar", ".war",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt",
    ".so", ".dll", ".dylib", ".exe", ".bin", ".o", ".a", ".class", ".pyc", ".pyo",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".db", ".sqlite", ".sqlite3", ".mdb", ".iso", ".img", ".dmg",
    ".lock", ".min.js", ".min.css", ".map",
})

BINARY_PROBE_BYTES = 8192

# UTF-16/32 encode ASCII with NUL padding, so the "contains NUL byte ⇒ binary"
# probe rejects them outright. Windows tooling (PowerShell redirects, .NET
# config, registry exports) emits UTF-16LE routinely, so those files have to be
# recognised before the probe runs or their secrets are never scanned at all.
# UTF-32 BOMs are checked first: BOM_UTF32_LE starts with BOM_UTF16_LE.
_BOMS: tuple[tuple[bytes, str], ...] = (
    (codecs.BOM_UTF32_LE, "utf-32-le"),
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)


def detect_encoding(head: bytes) -> str | None:
    """Return a codec name for `head`, or None if it looks like real binary.

    After the BOM check, BOM-less UTF-16 is inferred from the *alternation*:
    ASCII in UTF-16LE is `c\\x00c\\x00...`, so one side of each pair is NUL and
    the other side is printable text.

    Testing only the NUL side is not enough. An ELF header is ~82% NUL with 88%
    of them on odd offsets, which mimics UTF-16LE perfectly — but its even
    offsets are mostly NUL too, whereas real UTF-16LE has readable characters
    there. Both sides must therefore be checked.
    """
    for bom, enc in _BOMS:
        if head.startswith(bom):
            return enc

    sample = head[:4096]
    if len(sample) < 16 or sample.count(0) < len(sample) * 0.25:
        return None if b"\x00" in sample else "utf-8"

    def is_text(b: int) -> bool:
        return b in (9, 10, 13) or 32 <= b < 127

    pairs = len(sample) // 2
    lo = sample[0 : 2 * pairs : 2]
    hi = sample[1 : 2 * pairs : 2]
    threshold = pairs * 0.8
    if hi.count(0) > threshold and sum(map(is_text, lo)) > threshold:
        return "utf-16-le"
    if lo.count(0) > threshold and sum(map(is_text, hi)) > threshold:
        return "utf-16-be"
    return None


# --------------------------------------------------------------------------- #
# Core scanning
# --------------------------------------------------------------------------- #


def _windows(line: str, max_len: int, overlap: int) -> Iterator[tuple[int, str]]:
    """Split an over-long line into overlapping windows.

    Minified bundles routinely put megabytes on a single line. Scanning such a
    line whole is slow; skipping it outright loses real findings. Overlapping
    windows bound the cost while still catching any secret shorter than the
    overlap that straddles a boundary.
    """
    if len(line) <= max_len:
        yield 0, line
        return
    step = max_len - overlap
    for start in range(0, len(line), step):
        chunk = line[start : start + max_len]
        if not chunk:
            break
        yield start, chunk
        if start + max_len >= len(line):
            break


_ENTROPY_BLOB_RE = re.compile(r"[A-Za-z0-9+/=_\-]{32,}")


def scan_line(
    ruleset: RuleSet,
    cfg: ScanConfig,
    path: str,
    line_no: int,
    line: str,
    stats: Stats,
) -> list[Finding]:
    findings: list[Finding] = []
    for offset, window in _windows(line, cfg.max_line_length, cfg.line_overlap):
        # Lowercase once, then reuse for the trigger, the ignore pragma and the
        # candidate lookup. This is the hot path: it runs on every line scanned.
        lowered = window.lower()
        if not ruleset.trigger.search(lowered):
            continue
        if cfg.respect_inline_ignore and has_inline_ignore(lowered):
            continue
        stats.lines_triggered += 1
        for idx in ruleset.candidates(lowered):
            cr = ruleset.compiled[idx]
            rule = cr.rule
            for m in cr.regex.finditer(window):
                secret = m.group(1) if cr.regex.groups else m.group(0)
                if not secret:
                    continue

                threshold = (
                    cfg.min_entropy_override
                    if cfg.min_entropy_override is not None
                    else rule.min_entropy
                )
                ent = shannon_entropy(secret)
                if ent < threshold:
                    continue
                if cfg.filter_placeholders and looks_like_placeholder(secret):
                    continue
                if rule.generic and looks_like_non_secret(secret):
                    continue

                col = offset + m.start(1 if cr.regex.groups else 0) + 1
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=int(rule.severity),
                        path=path,
                        line=line_no,
                        column=col,
                        secret=secret,
                        entropy=ent,
                        preview=_make_preview(window, m, secret, cfg.preview_width),
                        fingerprint=fingerprint(rule.id, path, secret),
                    )
                )

    if cfg.entropy_scan:
        findings.extend(_entropy_scan_line(cfg, path, line_no, line))
    return findings


def _entropy_scan_line(cfg: ScanConfig, path: str, line_no: int, line: str) -> list[Finding]:
    """Opt-in detector for unstructured high-entropy blobs.

    This is what the original script's `Base64` rule was reaching for. It is
    off by default because it cannot distinguish a leaked key from a hash, a
    checksum, or a minified identifier — it is a triage aid, not a detector.
    """
    out: list[Finding] = []
    for m in _ENTROPY_BLOB_RE.finditer(line[: cfg.max_line_length]):
        blob = m.group(0)
        ent = shannon_entropy(blob)
        if ent < cfg.entropy_scan_threshold:
            continue
        if cfg.filter_placeholders and looks_like_placeholder(blob):
            continue
        out.append(
            Finding(
                rule_id="high-entropy-blob",
                rule_name="High-Entropy String",
                severity=int(Severity.LOW),
                path=path,
                line=line_no,
                column=m.start() + 1,
                secret=blob,
                entropy=ent,
                preview=_make_preview(line, m, blob, cfg.preview_width),
                fingerprint=fingerprint("high-entropy-blob", path, blob),
            )
        )
    return out


def _make_preview(line: str, match: re.Match, secret: str, width: int) -> str:
    """Context snippet with the credential masked.

    A report that quotes the raw line is itself a secret-bearing artifact — it
    ends up in CI logs and tickets. The preview always carries the redacted form.
    """
    masked = line.replace(secret, redact(secret))
    masked = masked.strip()
    if len(masked) <= width:
        return masked
    center = max(0, match.start() - width // 3)
    snippet = masked[center : center + width]
    return ("…" if center > 0 else "") + snippet.strip() + "…"


def read_text_file(path: Path, cfg: ScanConfig, stats: Stats) -> str | None:
    """Read a file as text, rejecting binaries and oversized files.

    Reads bytes and decodes once rather than iterating a text-mode file: it is
    measurably faster and lets us probe for NUL bytes before committing to the
    whole file.
    """
    try:
        with path.open("rb") as f:
            # Never probe past the size limit: with a small --max-file-size the
            # probe would otherwise overshoot it, and the follow-up read length
            # would go negative and raise, mis-reporting an oversized file as
            # unreadable.
            head = f.read(min(BINARY_PROBE_BYTES, cfg.max_file_size + 1))
            encoding = detect_encoding(head)
            if encoding is None:
                stats.files_skipped_binary += 1
                return None
            if len(head) > cfg.max_file_size:
                stats.files_skipped_large += 1
                return None
            # len(head) <= max_file_size here, so this length is always >= 1.
            rest = f.read(cfg.max_file_size - len(head) + 1)
    except (OSError, ValueError):
        stats.files_unreadable += 1
        return None

    data = head + rest
    if len(data) > cfg.max_file_size:
        stats.files_skipped_large += 1
        return None

    stats.bytes_scanned += len(data)
    # A truncated final UTF-16 code unit would otherwise raise; "replace" keeps
    # the rest of the file scannable. lstrip drops a BOM the codec left behind.
    return data.decode(encoding, errors="replace").lstrip("﻿")


def scan_file(path: Path, ruleset: RuleSet, cfg: ScanConfig) -> tuple[list[Finding], Stats]:
    stats = Stats()
    text = read_text_file(path, cfg, stats)
    if text is None:
        return [], stats

    stats.files_scanned += 1
    findings: list[Finding] = []
    path_str = str(path)
    for line_no, line in enumerate(text.splitlines(), 1):
        stats.lines_scanned += 1
        if line:
            findings.extend(scan_line(ruleset, cfg, path_str, line_no, line, stats))
    return findings, stats


# --------------------------------------------------------------------------- #
# File discovery
# --------------------------------------------------------------------------- #


def iter_files(
    targets: Iterable[Path],
    exclude_dirs: frozenset[str],
    exclude_exts: frozenset[str],
    stats: Stats,
    follow_symlinks: bool = False,
) -> Iterator[Path]:
    """Yield candidate files, recording discovery-time skips into `stats`.

    Uses os.scandir directly rather than os.walk: scandir exposes the directory
    entry's cached type, so deciding "directory or file" costs no extra syscall.

    Extension skips are counted here rather than in the workers because this is
    where they happen — the file is never handed to a worker at all.

    With --follow-symlinks, directories and files are tracked by (device, inode)
    so a symlink cycle terminates on detection and a file reachable by several
    paths is scanned once. Without the flag there is nothing to track, so the
    default path stays free of the extra stat() calls.
    """
    seen_dirs: set[tuple[int, int]] = set()
    seen_files: set[tuple[int, int]] = set()

    def first_visit(seen: set[tuple[int, int]], stat_result: os.stat_result) -> bool:
        key = (stat_result.st_dev, stat_result.st_ino)
        if key in seen:
            return False
        seen.add(key)
        return True

    for target in targets:
        if target.is_file():
            yield target
            continue
        stack = [target]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        try:
                            if entry.is_dir(follow_symlinks=follow_symlinks):
                                if entry.name in exclude_dirs:
                                    continue
                                if follow_symlinks and not first_visit(seen_dirs, entry.stat()):
                                    continue  # symlink cycle or already-walked tree
                                stack.append(Path(entry.path))
                            elif entry.is_file(follow_symlinks=follow_symlinks):
                                name = entry.name.lower()
                                if any(name.endswith(ext) for ext in exclude_exts):
                                    stats.files_skipped_ext += 1
                                    continue
                                if follow_symlinks and not first_visit(seen_files, entry.stat()):
                                    continue  # same file reached by another path
                                yield Path(entry.path)
                        except OSError:
                            continue
            except (OSError, PermissionError):
                continue


def git_tracked_files(root: Path) -> list[Path] | None:
    """List git-tracked files, so .gitignore is honoured for free.

    Re-implementing .gitignore semantics correctly is a project in itself;
    delegating to git is both shorter and right.
    """
    import subprocess

    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            capture_output=True,
            timeout=60,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    names = proc.stdout.decode("utf-8", "replace").split("\0")
    return [root / n for n in names if n]


# --------------------------------------------------------------------------- #
# Parallel execution
# --------------------------------------------------------------------------- #

_WORKER_RULESET: RuleSet | None = None
_WORKER_CFG: ScanConfig | None = None


def _init_worker(rules: list[Rule], cfg: ScanConfig) -> None:
    """Compile the ruleset once per worker process.

    Compiled regex objects are picklable, but shipping them per task would
    re-serialise them for every chunk. Compiling once in the initializer keeps
    the per-task payload to a single path string.
    """
    global _WORKER_RULESET, _WORKER_CFG
    _WORKER_RULESET = RuleSet(rules)
    _WORKER_CFG = cfg


def _scan_one(path_str: str) -> tuple[list[Finding], Stats]:
    assert _WORKER_RULESET is not None and _WORKER_CFG is not None
    return scan_file(Path(path_str), _WORKER_RULESET, _WORKER_CFG)


def run_scan(
    paths: list[Path],
    rules: list[Rule],
    cfg: ScanConfig,
    jobs: int,
) -> tuple[list[Finding], Stats]:
    total_stats = Stats()
    findings: list[Finding] = []

    # Process startup costs ~30-80 ms each; below a few hundred files the pool
    # is slower than doing the work inline.
    if jobs <= 1 or len(paths) < 200:
        ruleset = RuleSet(rules)
        for p in paths:
            f, s = scan_file(p, ruleset, cfg)
            findings.extend(f)
            total_stats.merge(s)
        return findings, total_stats

    chunksize = max(1, min(64, len(paths) // (jobs * 8) or 1))
    with cf.ProcessPoolExecutor(
        max_workers=jobs, initializer=_init_worker, initargs=(rules, cfg)
    ) as pool:
        for f, s in pool.map(_scan_one, [str(p) for p in paths], chunksize=chunksize):
            findings.extend(f)
            total_stats.merge(s)
    return findings, total_stats


# --------------------------------------------------------------------------- #
# Baseline
# --------------------------------------------------------------------------- #


class UsageError(Exception):
    """A caller mistake. Distinct from "secrets found" so CI can tell them apart:
    exit 1 means findings, exit 2 means the scan never ran properly."""


def load_baseline(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UsageError(f"cannot read baseline {path}: {exc}") from exc
    return set(data.get("fingerprints", []))


def write_baseline(path: Path, findings: Sequence[Finding]) -> None:
    payload = {
        "version": __version__,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "fingerprints": sorted({f.fingerprint for f in findings}),
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #


class Palette:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _w(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, t: str) -> str:
        return self._w("1", t)

    def dim(self, t: str) -> str:
        return self._w("2", t)

    def sev(self, severity: Severity, t: str) -> str:
        return self._w({
            Severity.CRITICAL: "1;97;41",
            Severity.HIGH: "1;31",
            Severity.MEDIUM: "1;33",
            Severity.LOW: "36",
        }[severity], t)


def report_console(
    findings: Sequence[Finding],
    stats: Stats,
    palette: Palette,
    show_secrets: bool,
    show_stats: bool,
    stream=sys.stdout,
) -> None:
    if not findings:
        print(palette.bold("No secrets detected."), file=stream)
    else:
        by_file: dict[str, list[Finding]] = {}
        for f in findings:
            by_file.setdefault(f.path, []).append(f)

        for path in sorted(by_file):
            print(f"\n{palette.bold(path)}", file=stream)
            for f in sorted(by_file[path], key=lambda x: (x.line, x.column)):
                sev = Severity(f.severity)
                value = f.secret if show_secrets else f.redacted_secret()
                print(
                    f"  {palette.sev(sev, f' {sev.label:<8} ')} "
                    f"{f.line}:{f.column}  {f.rule_name} "
                    f"{palette.dim(f'[{f.rule_id}]')}",
                    file=stream,
                )
                print(f"      secret : {value}", file=stream)
                print(f"      context: {palette.dim(f.preview)}", file=stream)
                print(
                    palette.dim(f"      entropy: {f.entropy:.2f} bits/char   fp: {f.fingerprint}"),
                    file=stream,
                )

        counts = Counter(Severity(f.severity).label for f in findings)
        summary = "  ".join(
            f"{sev.label}: {counts.get(sev.label, 0)}" for sev in sorted(Severity, reverse=True)
        )
        print(f"\n{palette.bold(f'{len(findings)} finding(s)')}   {summary}", file=stream)

    if show_stats:
        print(
            palette.dim(
                f"\nscanned {stats.files_scanned} files "
                f"({stats.bytes_scanned / 1e6:.1f} MB, {stats.lines_scanned} lines); "
                f"skipped {stats.files_skipped_ext} by extension, "
                f"{stats.files_skipped_binary} binary, "
                f"{stats.files_skipped_large} oversized, "
                f"{stats.files_unreadable} unreadable; "
                f"{stats.lines_triggered} lines passed the keyword pre-filter"
            ),
            file=stream,
        )


def report_json(findings: Sequence[Finding], stats: Stats, show_secrets: bool, stream) -> None:
    payload = {
        "version": __version__,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "stats": {k: getattr(stats, k) for k in stats.__dataclass_fields__},
        "findings": [f.to_dict(show_secrets) for f in findings],
    }
    json.dump(payload, stream, indent=2)
    stream.write("\n")


_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def report_sarif(findings: Sequence[Finding], ruleset: RuleSet, stream) -> None:
    """SARIF 2.1.0 — consumable by GitHub Code Scanning, Azure DevOps, VS Code."""
    used = sorted({f.rule_id for f in findings})
    rule_defs = []
    for rid in used:
        rule = ruleset.by_id(rid)
        rule_defs.append({
            "id": rid,
            "name": rule.name if rule else rid,
            "shortDescription": {"text": rule.name if rule else rid},
            "defaultConfiguration": {
                "level": _SARIF_LEVEL[Severity(rule.severity)] if rule else "note"
            },
        })

    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[Severity(f.severity)],
            "message": {"text": f"{f.rule_name} detected ({f.redacted_secret()})"},
            "partialFingerprints": {"secretsFinder/v1": f.fingerprint},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": Path(f.path).as_posix()},
                    "region": {"startLine": f.line, "startColumn": f.column},
                }
            }],
        })

    json.dump({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "secrets-finder",
                "version": __version__,
                "informationUri": "https://github.com/",
                "rules": rule_defs,
            }},
            "results": results,
        }],
    }, stream, indent=2)
    stream.write("\n")


def report_csv(findings: Sequence[Finding], show_secrets: bool, stream) -> None:
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(["severity", "rule_id", "rule_name", "file", "line", "column", "secret", "entropy", "fingerprint"])
    for f in findings:
        writer.writerow([
            Severity(f.severity).label, f.rule_id, f.rule_name, f.path, f.line, f.column,
            f.secret if show_secrets else f.redacted_secret(), f"{f.entropy:.3f}", f.fingerprint,
        ])


# --------------------------------------------------------------------------- #
# Self-test
# --------------------------------------------------------------------------- #

CLEAN_CORPUS = [
    "def compute_total(items):",
    "    return sum(item.price for item in items)",
    "# See https://example.com/docs for details",
    "import hashlib, base64",
    'logger.info("connection established to %s", host)',
    "const hash = 'd41d8cd98f00b204e9800998ecf8427e';",  # md5, not a credential
    "SELECT id, name FROM users WHERE active = 1;",
    'password_field.set_placeholder("Enter your password")',
    "AWS_REGION=eu-west-3",
    "// eyJhbGciOiJIUzI1NiJ9 is a JWT header prefix",
]


def self_test(verbose: bool) -> int:
    """Verify every rule fires on its own example and stays quiet on clean code."""
    ruleset = RuleSet(RULES)
    cfg = ScanConfig(filter_placeholders=False)
    failures: list[str] = []

    for rule in RULES:
        stats = Stats()
        hits = scan_line(ruleset, cfg, "<self-test>", 1, rule.example, stats)
        ids = {h.rule_id for h in hits}
        if rule.id not in ids:
            failures.append(f"  {rule.id}: example did not match (matched instead: {sorted(ids) or 'nothing'})")
        elif verbose:
            hit = next(h for h in hits if h.rule_id == rule.id)
            print(f"  ok  {rule.id:<28} -> {hit.redacted_secret()}")

    strict_cfg = ScanConfig()
    for i, line in enumerate(CLEAN_CORPUS, 1):
        stats = Stats()
        hits = scan_line(ruleset, strict_cfg, "<clean>", i, line, stats)
        for h in hits:
            failures.append(f"  false positive on clean line {i}: {h.rule_id} -> {h.redacted_secret()}\n      {line}")

    print(f"\nrules: {len(RULES)}   keywords: {len(ruleset.keyword_index)}   clean corpus: {len(CLEAN_CORPUS)} lines")
    if failures:
        print(f"\nFAILED ({len(failures)}):")
        for f in failures:
            print(f)
        return 1
    print("self-test passed")
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def parse_size(value: str) -> int:
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([kmg]?)b?", value.strip(), re.IGNORECASE)
    if not m:
        raise argparse.ArgumentTypeError(f"invalid size: {value!r} (try 10M, 512K, 2G)")
    return int(float(m.group(1)) * {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}[m.group(2).lower()])


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secrets-finder",
        description="Fast, low-false-positive scanner for hardcoded credentials.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "exit codes:\n"
            "  0  no findings at or above --fail-on\n"
            "  1  findings reported\n"
            "  2  usage or I/O error\n\n"
            "examples:\n"
            "  secrets-finder .\n"
            "  secrets-finder . --git-tracked --format sarif -o results.sarif\n"
            "  secrets-finder src/ --min-severity HIGH --fail-on high\n"
            "  secrets-finder . --write-baseline .secrets-baseline.json\n"
        ),
    )
    p.add_argument("targets", nargs="*", type=Path, help="files or directories to scan")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    out = p.add_argument_group("output")
    out.add_argument("-f", "--format", choices=["console", "json", "sarif", "csv"], default="console")
    out.add_argument("-o", "--output", type=Path, help="write the report to a file instead of stdout")
    out.add_argument("--show-secrets", action="store_true", help="print credentials unredacted (off by default)")
    out.add_argument("--stats", action="store_true", help="print scan statistics")
    out.add_argument("--no-color", action="store_true")
    out.add_argument("-q", "--quiet", action="store_true")

    filt = p.add_argument_group("filtering")
    filt.add_argument("--min-severity", type=Severity.parse, default=Severity.LOW,
                      metavar="LEVEL", help="LOW | MEDIUM | HIGH | CRITICAL (default: LOW)")
    filt.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"], default="low",
                      help="minimum severity that makes the run exit 1 (default: low)")
    filt.add_argument("--min-entropy", type=float, metavar="BITS",
                      help="override every rule's entropy threshold")
    filt.add_argument("--no-placeholder-filter", action="store_true",
                      help="do not suppress example/placeholder values")
    filt.add_argument("--no-inline-ignore", action="store_true",
                      help="ignore 'pragma: allowlist secret' comments")
    filt.add_argument("--rule", action="append", metavar="ID", help="only run these rules (repeatable)")
    filt.add_argument("--exclude-rule", action="append", metavar="ID", help="skip these rules (repeatable)")
    filt.add_argument("--entropy-scan", action="store_true",
                      help="also report unstructured high-entropy strings (noisy)")
    filt.add_argument("--all-matches", action="store_true",
                      help="report every rule that matched, including overlapping ones")

    disc = p.add_argument_group("discovery")
    disc.add_argument("--exclude-dir", action="append", default=[], metavar="NAME")
    disc.add_argument("--include-dir", action="append", default=[], metavar="NAME",
                      help="scan a directory that is excluded by default")
    disc.add_argument("--git-tracked", action="store_true",
                      help="scan only files git knows about (honours .gitignore)")
    disc.add_argument("--follow-symlinks", action="store_true")
    disc.add_argument("--max-file-size", type=parse_size, default="10M", metavar="SIZE")
    disc.add_argument("--max-line-length", type=int, default=4096, metavar="N")

    perf = p.add_argument_group("performance")
    perf.add_argument("-j", "--jobs", type=int, default=0,
                      help="worker processes (default: CPU count; 1 disables multiprocessing)")

    base = p.add_argument_group("baseline")
    base.add_argument("--baseline", type=Path, help="suppress findings listed in this baseline file")
    base.add_argument("--write-baseline", type=Path, help="write current findings to a baseline and exit 0")

    misc = p.add_argument_group("introspection")
    misc.add_argument("--list-rules", action="store_true")
    misc.add_argument("--self-test", action="store_true", help="verify every rule against its test vector")

    return p


def select_rules(rule_ids: list[str] | None, exclude_ids: list[str] | None) -> list[Rule]:
    known = {r.id for r in RULES}
    for group in (rule_ids or [], exclude_ids or []):
        for rid in group:
            if rid not in known:
                raise UsageError(f"unknown rule id {rid!r} (see --list-rules)")
    rules = RULES
    if rule_ids:
        rules = [r for r in rules if r.id in set(rule_ids)]
    if exclude_ids:
        rules = [r for r in rules if r.id not in set(exclude_ids)]
    if not rules:
        raise UsageError("rule selection left nothing to scan with")
    return list(rules)


def list_rules(palette: Palette) -> None:
    print(f"{len(RULES)} rules\n")
    for r in sorted(RULES, key=lambda x: (-int(x.severity), x.id)):
        sev = Severity(r.severity)
        ent = f"entropy>={r.min_entropy}" if r.min_entropy else "structural"
        print(f"  {palette.sev(sev, f' {sev.label:<8} ')} {r.id:<30} {r.name}")
        print(palette.dim(f"      {ent}   keywords: {', '.join(r.keywords[:6])}"))


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    use_color = sys.stdout.isatty() and not args.no_color and not os.environ.get("NO_COLOR")
    palette = Palette(use_color)

    if args.self_test:
        return self_test(verbose=not args.quiet)
    if args.list_rules:
        list_rules(palette)
        return 0
    if not args.targets:
        parser.error("at least one target is required (or use --self-test / --list-rules)")

    for t in args.targets:
        if not t.exists():
            print(f"error: target not found: {t}", file=sys.stderr)
            return 2

    rules = select_rules(args.rule, args.exclude_rule)
    cfg = ScanConfig(
        max_file_size=args.max_file_size,
        max_line_length=args.max_line_length,
        min_entropy_override=args.min_entropy,
        filter_placeholders=not args.no_placeholder_filter,
        respect_inline_ignore=not args.no_inline_ignore,
        entropy_scan=args.entropy_scan,
    )

    exclude_dirs = (DEFAULT_EXCLUDE_DIRS | set(args.exclude_dir)) - set(args.include_dir)

    # -- discovery ---------------------------------------------------------- #
    started = time.perf_counter()
    discovery_stats = Stats()
    paths: list[Path] = []
    if args.git_tracked:
        for t in args.targets:
            root = t if t.is_dir() else t.parent
            tracked = git_tracked_files(root)
            if tracked is None:
                print(f"error: --git-tracked given but {root} is not a git repository", file=sys.stderr)
                return 2
            paths.extend(
                p for p in tracked
                if p.is_file() and not any(part in exclude_dirs for part in p.parts)
            )
    else:
        paths = list(iter_files(args.targets, frozenset(exclude_dirs), DEFAULT_EXCLUDE_EXTS,
                                discovery_stats, args.follow_symlinks))
    paths = sorted(set(paths))

    jobs = args.jobs if args.jobs > 0 else (os.cpu_count() or 1)

    # -- scan --------------------------------------------------------------- #
    try:
        findings, stats = run_scan(paths, rules, cfg, jobs)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 2
    stats.merge(discovery_stats)
    elapsed = time.perf_counter() - started

    # -- post-processing ---------------------------------------------------- #
    # Order matters: collapse duplicates and overlaps *before* filtering by
    # severity, otherwise dropping a specific-but-low-severity rule would leave
    # its generic twin behind and the same secret would still be reported.
    seen: set[tuple] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.path, f.line, f.column, f.secret)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    findings = unique

    if not args.all_matches:
        findings = suppress_overlaps(findings)

    findings = [f for f in findings if f.severity >= int(args.min_severity)]
    if args.baseline:
        suppressed = load_baseline(args.baseline)
        findings = [f for f in findings if f.fingerprint not in suppressed]

    findings = sorted(findings, key=lambda f: (-f.severity, f.path, f.line, f.column))

    if args.write_baseline:
        write_baseline(args.write_baseline, findings)
        if not args.quiet:
            print(f"baseline written to {args.write_baseline} ({len(findings)} fingerprints)")
        return 0

    # -- report ------------------------------------------------------------- #
    ruleset = RuleSet(RULES)
    stream = open(args.output, "w", encoding="utf-8", newline="") if args.output else sys.stdout
    try:
        if args.format == "console":
            report_console(findings, stats, Palette(use_color and not args.output),
                           args.show_secrets, args.stats, stream)
            if args.stats:
                rate = stats.files_scanned / elapsed if elapsed else 0
                print(Palette(use_color and not args.output).dim(
                    f"completed in {elapsed:.2f}s using {jobs} worker(s) — {rate:,.0f} files/s"
                ), file=stream)
        elif args.format == "json":
            report_json(findings, stats, args.show_secrets, stream)
        elif args.format == "sarif":
            report_sarif(findings, ruleset, stream)
        elif args.format == "csv":
            report_csv(findings, args.show_secrets, stream)
    finally:
        if args.output:
            stream.close()
            if not args.quiet:
                print(f"report written to {args.output} ({len(findings)} finding(s))")

    if args.fail_on == "none":
        return 0
    threshold = Severity.parse(args.fail_on)
    return 1 if any(f.severity >= int(threshold) for f in findings) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except UsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(2)
