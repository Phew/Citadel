# Protocol specifications

Normative flow and crypto specs live here and must stay in sync with
`citadel-proto` and implementations (AGENTS.md rule 5: citadel-proto is
canonical for wire contracts; amend docs when they diverge).

| Doc | Milestone | Owner |
|-----|-----------|--------|
| auth.md — registration + KT verification (F1) | M1 | Opus + K3 |
| (DM / channel MLS) | M2–M3 | Opus |
| franking.md | M6 (write first) | Opus |

`auth.md` pins the client KT verification flow (F1); auth-flow operational
parameters live in ADR-0003 and KT log design in ADR-0001.
