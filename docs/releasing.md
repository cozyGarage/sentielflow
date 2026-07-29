# Releasing SentinelFlow

GoReleaser publishes GitHub Release assets (`checksums.txt` + platform archives) on `v*` tags. Docker Hub images are published **when** `DOCKER_USERNAME` / `DOCKER_PASSWORD` are set; otherwise the workflow uses `--skip=docker` so binaries still ship.

## Prerequisites

| Secret | Required? | Purpose |
| --- | --- | --- |
| `GITHUB_TOKEN` | Automatic | Create GitHub Release + upload assets |
| `DOCKER_USERNAME` | Optional | Docker Hub username for `sentinelflow/sentinelflow` |
| `DOCKER_PASSWORD` | Optional | Docker Hub access token (or password) |

Pinned tooling: `goreleaser/goreleaser-action@v6.3.0` + GoReleaser CLI `v2.9.0`.

## Cut a release

```bash
git checkout main
git pull origin main
git tag -a v1.1.0 -m "SentinelFlow v1.1.0"
git push origin v1.1.0
```

Watch the **Release** workflow. On success:

- GitHub Release `v1.1.0` includes binaries + `checksums.txt`
- If Docker Hub secrets are present: `sentinelflow/sentinelflow:v1.1.0`, `:v1`, `:v1.1`, `:latest`
- Install path: `curl -fsSL …/scripts/install.sh | bash` (verifies checksums)

## Verify

```bash
VERSION=1.1.0 ./scripts/install.sh
./bin/sentinelflow version

# Only if Docker Hub publish ran:
docker pull sentinelflow/sentinelflow:v1.1.0
docker run --rm sentinelflow/sentinelflow:v1.1.0 version
```

## Module path note

The Go module path is `github.com/cozygarage/sentinelflow` while the GitHub repository is `cozyGarage/sentielflow`. Do **not** advertise `go install github.com/cozyGarage/sentielflow@…` until those names are aligned (rename is intentionally deferred). Prefer release binaries, Docker, or `make build`.
