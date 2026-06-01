# vault-bridge-agent

Customer-side outbound proxy daemon for the PodMaker
vault flow. Source of truth lives in the private monorepo
at `podmaker-sh/podmaker` under `apps/vault-bridge-agent`.
This repo is a read-only mirror, refreshed by the
`publish-vault-bridge-agent` workflow on every push to
`main` and every `bridge-v*` release tag.

## Install

```sh
curl -fsSL https://app.podmaker.sh/install/vault-bridge | sh

# or
brew tap podmaker-sh/tap
brew install podmaker-vault-bridge
```

## Pre-built binaries

See [releases](https://github.com/podmaker-sh/releases/releases)
for tagged binaries, checksums, and cosign signatures.

## Issues + PRs

File against the public mirror — they are forwarded to
the monorepo by the maintainers.
