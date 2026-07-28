# Releasing SentinelFlow

GoReleaser publishes GitHub Release assets (`checksums.txt` + platform archives) and Docker Hub images when a `v*` tag is pushed.

## Prerequisites

Repository secrets (Settings → Secrets and variables → Actions):

| Secret | Purpose |
| --- | --- |
| `DOCKER_USERNAME` | Docker Hub username with push access to `sentinelflow/sentinelflow` |
| `DOCKER_PASSWORD` | Docker Hub access token (or password) |

The release workflow (`.github/workflows/release.yml`) pins `goreleaser/goreleaser-action@v6.3.0` and GoReleaser CLI `v2.9.0`.

## Cut a release

After Wave 1–2 correctness/delivery changes are on `main`:

```bash
git checkout main
git pull origin main
git tag -a v1.1.0 -m "SentinelFlow v1.1.0"
git push origin v1.1.0
```

Watch the **Release** workflow. On success:

- GitHub Release `v1.1.0` includes binaries + `checksums.txt`
- Images: `sentinelflow/sentinelflow:v1.1.0`, `:v1`, `:v1.1`, `:latest`
- Install path: `curl -fsSL …/scripts/install.sh | bash` (verifies checksums)

## Verify

```bash
VERSION=1.1.0 ./scripts/install.sh
./bin/sentinelflow version

docker pull sentinelflow/sentinelflow:v1.1.0
docker run --rm sentinelflow/sentinelflow:v1.1.0 version
```

## Module path note

The Go module path is `github.com/cozygarage/sentinelflow` while the GitHub repository is `cozyGarage/sentielflow`. Do **not** advertise `go install github.com/cozyGarage/sentielflow@…` until those names are aligned (rename is intentionally deferred). Prefer release binaries, Docker, or `make build`.
