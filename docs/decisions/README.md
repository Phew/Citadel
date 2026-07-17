# Architecture Decision Records (ADRs)

A decision exists only when committed here (AGENTS.md rule 3). Chat messages
and PROPOSED drafts authorize nothing. **PROPOSED → ACCEPTED** only by a commit
from charge (human).

## Status values

| Status     | Meaning                                              |
|------------|------------------------------------------------------|
| PROPOSED   | Agent or human draft; not binding                    |
| ACCEPTED   | charge has accepted; binding for implementers        |
| SUPERSEDED | Replaced by a later ADR (link it)                    |
| REJECTED   | Explicitly not taken                                 |

## Naming

```
ADR-NNNN-short-kebab-title.md
```

Numbers are zero-padded four digits, assigned in commit order. Do not reuse
numbers. Copy `0000-template.md` to start a new record.

## When to write an ADR

- Any choice not specified in `plans/PLAN.md`
- MSRV / toolchain bumps (PLAN.md §13)
- Substituting a fixed stack technology (PLAN.md §4)
- Security-relevant API or protocol changes

Crypto and protocol ADRs are design-reviewed by K3 before charge accepts them
(AGENTS.md review structure).
