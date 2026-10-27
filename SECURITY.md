# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately, not in a public issue:

- **GitHub private vulnerability reporting:**
  https://github.com/rahulsub/synapse-mem/security/advisories/new

Include the version (`smem version`), what you did, what happened, what you
expected, and the impact as you see it. A minimal reproduction helps most.

## What to expect

| When | What |
|---|---|
| within 3 business days | acknowledgement of your report |
| within 10 business days | an assessment: whether it is a vulnerability, and its severity |
| within 90 days | a fix released, or an agreed plan if it needs longer |

We coordinate disclosure with you. A GitHub security advisory is published
when the fix is released, with credit to you unless you prefer otherwise.
Please don't disclose the issue publicly before then.

## Supported versions

| Version | Supported |
|---|---|
| latest release (0.4.x) | yes |
| older releases | no: please upgrade |

## Scope

Especially welcome: ways to

- modify, forge or reorder events without `smem verify` noticing;
- get synced data from an untrusted key into recall, context or review;
- make smem run code, or send credentials anywhere, from a committed
  `.smem/config.json` or from synced data;
- get secrets past redaction into the signed log, or to a judge or checker;
- read files outside the project as fact-check evidence.

`docs/DESIGN.md` §7 describes what the signatures do and don't guarantee:
the log is tamper-evident, not tamper-proof. Someone with full control of a
machine can rewrite that machine's own history; what they can't do is make
other replicas accept it.
