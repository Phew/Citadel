# Citadel deploy (local)

## Prerequisites

- Docker Engine with Compose v2
- Optional: [just](https://github.com/casey/just) for recipe shortcuts

## Bring-up

From the repository root:

```bash
just dev
# or
docker compose -f deploy/docker-compose.yml up -d --build
cargo run -p test-harness --bin wait-healthy -- --timeout-secs 120
```

## Published ports

| Service            | Port |
|--------------------|------|
| postgres           | 5432 |
| minio (S3 API)     | 9000 |
| minio console      | 9001 |
| auth-service       | 8081 |
| delivery-service   | 8082 |
| directory-service  | 8083 |
| blobstore-service  | 8084 |

Health: `GET http://127.0.0.1:<port>/health` → `{"status":"ok","service":"..."}`.

## Tear-down

```bash
just down      # keep volumes
just down-v    # wipe postgres + minio data
```
