# Backlog (adjacent improvements noticed, deliberately NOT in any diff yet)

Scope rule 1: items here are candidates for future tasks, not permissions to
sneak them into current PRs. charge picks them up (or assigns them) explicitly.

## CI / supply chain (k3 lane)

- **zizmor** static analysis for GitHub Actions workflows (finds
  template-injection and permission issues beyond what manual pinning catches).
  Add as a pinned CI job once charge approves the new tool dependency.
- **Dependabot/renovate for pinned Action SHAs** — pinned SHAs improve supply-
  chain safety but go stale; an automated bumper with version comments keeps
  hardening from rotting.

## Deploy (grok lane — flagged, not touched; scope rule 2)

- `deploy/docker-compose.yml` uses mutable image tags (`postgres:16-alpine`,
  `minio/minio:latest`, `minio/mc:latest`). Digest-pinning would make CI and
  the canary scan fully reproducible. Owner decision; noted here per
  AGENTS.md rule 2 etiquette (also relevant: M0 commit message said
  "lock Docker builds", but compose tags are still floating).

## Harness (k3 lane, later milestones)

- M5 blobstore bucket scanning for the canary scan is designed-for but not
  built in M1; tracked here so the extension isn't forgotten. (The M2
  message-path injection points landed with the M2 delivery build:
  authenticated + unauthenticated probes against POST
  /v1/groups/{gid}/messages, rejected before the store layer.)
