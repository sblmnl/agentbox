# Configuration examples

Complete, drop-in `agentbox.toml` files for common situations. Each is
valid on its own — copy one into your project root, adjust, and run
`agentbox config --origin` to see the effective merge and `agentbox doctor`
to preflight.

For the exhaustive key-by-key schema, see
[configuration.md](configuration.md) / `agentbox.toml(5)`. For how the seven
layers merge (and the `!reset` / `!value` array escapes), see the
[Layers](configuration.md#layers) section there — it governs everything
below. Every bundle named here is a real one; list them with
`agentbox bundles --list`.

## Contents

- [Minimal starter](#minimal-starter) — what `agentbox init` writes
- [Node / TypeScript web app](#node--typescript-web-app)
- [Python data project](#python-data-project)
- [Go service](#go-service)
- [.NET project](#net-project)
- [Polyglot monorepo with profiles](#polyglot-monorepo-with-profiles)
- [Air-gapped / offline](#air-gapped--offline)
- [Hardened VM tier](#hardened-vm-tier)
- [Enterprise: private registry + shared base](#enterprise-private-registry--shared-base)
- [Prebuilt or custom image](#prebuilt-or-custom-image)
- [Trusted host mounts and hooks](#trusted-host-mounts-and-hooks)
- [Many parallel boxes](#many-parallel-boxes)
- [User-global config](#user-global-config)
- [Matching `.agentignore` files](#matching-agentignore-files)

## Minimal starter

What `agentbox init` scaffolds — the smallest config worth committing.
Proxy egress, one agent bundle, `github`, container isolation.

```toml
# agentbox.toml — see agentbox.toml(5)
version = 1

[toolchains]
node = "24"

[network]
mode    = "proxy"
bundles = ["agent:claude-code", "github"]
allow   = []

[security]
min_isolation = "container"
```

Everything unset falls back to the built-in defaults (8 GB / 4 CPUs,
`mask_mode = "auto"`, `tree_mode = "auto"`, `read_only_root`, `cap_drop =
["ALL"]`, and so on). You only write what differs.

## Node / TypeScript web app

Node toolchain, npm registry reachable, an extra system package for native
builds, and one internal package registry added to the inherited allowlist.

```toml
version = 1

[box]
name = "webapp"

[toolchains]
node = "24"

[image]
packages = ["build-essential"]   # node-gyp / native addons

[network]
mode    = "proxy"
bundles = ["agent:claude-code", "github", "npm"]
allow   = ["npm.internal.example.com"]

[security]
min_isolation = "container"
```

`allow` **appends** to anything inherited from higher layers, so a teammate's
user-level config that already trusts an internal mirror keeps it.

## Python data project

Python plus PyPI, a chunk more memory for notebooks/models, and the
`copy` tree mode so extra boxes get an independent working tree even though
the repo may not use git worktrees cleanly.

```toml
version = 1

[toolchains]
python = "3.13"

[image]
packages = ["libpq-dev", "graphviz"]

[network]
mode    = "proxy"
bundles = ["agent:claude-code", "github", "pypi"]

[resources]
memory = "16g"
cpus   = 8

[security]
min_isolation = "container"
```

## Go service

Go module proxy, GitHub (source + `ghcr.io`), and setuid stripping left on
(the default) for a service image.

```toml
version = 1

[toolchains]
go = "1.26"

[network]
mode    = "proxy"
bundles = ["agent:claude-code", "github", "go"]

[security]
min_isolation = "container"
strip_setuid  = true
```

## .NET project

```toml
version = 1

[box]
default_agent = "claude"

[toolchains]
dotnet = "10"

[network]
mode    = "proxy"
bundles = ["agent:claude-code", "github", "nuget"]

[security]
min_isolation = "container"
```

## Polyglot monorepo with profiles

One workspace file at the repo root, per-area **profiles** selected with
`--profile`, `AGENTBOX_PROFILE`, or `[box].profile`. Exactly one workspace
file participates per repo; a subdirectory that needs different settings uses
a profile rather than its own `agentbox.toml`.

```toml
version = 1

[toolchains]
node = "24"                       # baseline for the whole repo

[network]
mode    = "proxy"
bundles = ["agent:claude-code", "github", "npm"]

[security]
min_isolation = "container"

# --- run: agentbox --profile backend claude ---
[profiles.backend]
[profiles.backend.toolchains]
go = "1.26"
[profiles.backend.network]
bundles = ["go"]                  # appended on top of the base bundles

# --- run: agentbox --profile ml claude ---
[profiles.ml]
[profiles.ml.toolchains]
python = "3.13"
[profiles.ml.network]
bundles = ["pypi"]
[profiles.ml.resources]
memory = "24g"
```

A profile overlays as its own layer above the workspace config, so
`profiles.ml.network.bundles` appends `pypi` to the base three rather than
replacing them.

## Air-gapped / offline

No egress at all. `network.mode = "none"` gives the guest no route out —
not even the proxy. Toolchains and packages must already be baked into the
image (or a prebuilt `image.ref`), since nothing can be fetched at run time.

```toml
version = 1

[image]
ref = "ghcr.io/acme/box-offline:2026-07"   # everything preinstalled

[network]
mode = "none"

[security]
min_isolation = "container"
```

You can also keep egress on normally and flip to offline per run with
`agentbox --offline claude`, or make it a profile:

```toml
[profiles.airgapped]
[profiles.airgapped.network]
mode = "none"
```

## Hardened VM tier

Require a hypervisor boundary, not a shared kernel. Under the `vm` tier
`guest_root = "allow"` and `nested_docker` become available (they are parse
errors under `[security.container]`). If no VM backend is available,
agentbox exits **69** naming what's missing — it never downgrades to a
container silently.

```toml
version = 1

[toolchains]
node = "24"

[network]
mode    = "proxy"
bundles = ["agent:claude-code", "github", "npm"]

[security]
min_isolation = "vm"
mask_mode     = "auto"            # under vm: "filter" (lookup-time, dynamic) where agentbox runs as root

[security.vm]
runtime        = "auto"           # "auto" | "kata" | "krun"
hypervisor     = "auto"           # "auto" | "qemu" | "cloud-hypervisor" | "libkrun"
guest_root     = "deny"           # tighten: no root inside the guest
nested_docker  = false
memory_backing = "balloon"
```

Note the vm tier's host-side mask view needs agentbox to run with
`CAP_SYS_ADMIN`; without it, mask mounts are expressed in the guest and
agentbox warns that guest-root could unmount them. See
[security.md](security.md).

## Enterprise: private registry + shared base

A committed project file that `extends` a company baseline checked in beside
it, adds an internal registry, and passes through the tokens the agent needs
without baking them into the image. `extends` includes the target as a
**lower-precedence** layer (cycles are detected).

`./agentbox.base.toml` (shared, referenced by many repos):

```toml
version = 1

[network]
mode    = "proxy"
bundles = ["agent:claude-code", "github"]
allow   = ["artifactory.corp.example.com"]

[security]
min_isolation = "container"
```

`./agentbox.toml` (this project):

```toml
version = 1
extends = "agentbox.base.toml"

[toolchains]
node = "24"

[network]
allow = ["npm.corp.example.com"]  # appends to the base allowlist

[variables]
TZ = "UTC"

[variables.passthrough]
names = ["ANTHROPIC_API_KEY", "GH_TOKEN", "NPM_TOKEN"]
```

`passthrough.names` forwards those host environment variables into the box
if they are set — nothing is written to disk or committed. To drop an
inherited allow entry rather than add one, use the array escapes, e.g.
`allow = ["!artifactory.corp.example.com"]` or `allow = ["!reset", ...]`.

## Prebuilt or custom image

Three mutually-exclusive ways to choose the image, highest precedence first.
Setting `ref` or `dockerfile` makes the `[toolchains]` keys inert (agentbox
warns when it ignores them). See
[Customizing the image](configuration.md#customizing-the-image) for the full
rules. The default path — just declare `base`, `packages`, and toolchains —
needs no Dockerfile at all:

```toml
version = 1

[toolchains]
node = "24"

[image]
base       = "ubuntu:26.04"                 # base agentbox layers its steps onto
packages   = ["postgresql-client", "jq"]    # extra apt packages on top of the baseline
build_args = { TZ = "UTC" }                 # part of the feature digest -> rebuilds on change

[network]
mode    = "proxy"
bundles = ["agent:claude-code", "github", "npm", "docker-hub"]  # docker-hub to pull the base
```

To take full ownership, point at a **prebuilt image** — nothing is layered
on, and toolchains/packages are ignored:

```toml
[image]
ref = "ghcr.io/acme/box:2026-07"
```

Or **bring your own Dockerfile** (path relative to this config's directory).
It is built as-is and re-digested by its contents, so editing it forces a
rebuild. It **must** honor agentbox's build-arg contract or uid mapping and
mask ownership break:

```toml
[image]
dockerfile = "Dockerfile"
```

A minimal conforming `./Dockerfile`:

```dockerfile
FROM ubuntu:26.04

# agentbox passes these in; the agent user MUST match the invoking uid/gid.
ARG AGENTBOX_UID
ARG AGENTBOX_GID
ARG AGENTBOX_GUEST_ROOT=deny        # "allow" | "deny", from the active tier's guest_root

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      git curl ca-certificates nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# Create the agent user with the passed-in ids, reclaiming any uid the base
# image already ships at that number (Ubuntu ships `ubuntu` at 1000).
RUN set -eu; \
    existing=$(getent passwd "$AGENTBOX_UID" | cut -d: -f1 || true); \
    if [ -n "$existing" ] && [ "$existing" != agent ]; then userdel -r "$existing" || userdel "$existing"; fi; \
    getent group "$AGENTBOX_GID" >/dev/null || groupadd -g "$AGENTBOX_GID" agent; \
    useradd -m -u "$AGENTBOX_UID" -g "$AGENTBOX_GID" -s /bin/bash agent

# Honor guest_root: sudo only when the tier allows a root guest.
RUN set -eu; \
    if [ "$AGENTBOX_GUEST_ROOT" = allow ]; then \
      apt-get update && apt-get install -y --no-install-recommends sudo && rm -rf /var/lib/apt/lists/*; \
      echo 'agent ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/agent; \
    else \
      apt-get purge -y sudo 2>/dev/null || true; \
    fi

USER agent
WORKDIR /home/agent
```

Confirm which image will run — and whether it's built locally or pulled —
with `agentbox config` or `agentbox --dry-run claude`; force a rebuild with
`agentbox build`.

## Trusted host mounts and hooks

`[[workspace.mounts]]` exposes host paths to the guest (bypassing masking),
and `[hooks]` commands run **on the host**. Because the workspace config is
committed, both are **refused (exit 77) until you review the file and run
`agentbox trust`**; any edit re-arms the check.

```toml
version = 1

[toolchains]
node = "24"

# Bypasses masking — only trusted, read-only, and minimal.
[[workspace.mounts]]
source = "~/.gitconfig"
target = "/home/agent/.gitconfig"
mode   = "ro"

[hooks]                           # run on the HOST, not in the box
pre_up  = ["./scripts/fetch-fixtures.sh"]
post_up = []

[network]
mode    = "proxy"
bundles = ["agent:claude-code", "github"]

[security]
min_isolation = "container"
```

After reviewing, run `agentbox trust` (check status with
`agentbox trust --show`). Prefer `[variables.passthrough]` over mounting
secret files: a passed-through env var is narrower than a mounted `~/.aws`.

## Many parallel boxes

Run several agents on the same repo at once. `tree_mode = "worktree"` gives
each extra box its own `git worktree` on an `agentbox/<instance>` branch, so
they never trample each other or your checkout; `max_boxes` caps the count.

```toml
version = 1

[box]
idle_timeout = "20m"              # auto-stop (never remove) after idle

[project]
max_boxes = 6

[workspace]
tree_mode = "worktree"

[network]
mode    = "proxy"
bundles = ["agent:claude-code", "github", "npm"]

[security]
min_isolation = "container"
```

`agentbox new --name exp` makes another box; `agentbox ls` shows each box's
backend, tier, tree mode, and age; `agentbox rm` removes a box but keeps its
branch unless you pass `--delete-branch`.

## User-global config

Machine-wide defaults live at `$XDG_CONFIG_HOME/agentbox/config.toml`
(usually `~/.config/agentbox/config.toml`) — a lower layer than any project
file. Good for cross-project limits and an allowlist you don't want to
restate per repo. `[limits]` belongs **here**, not in a project file.

```toml
version = 1

[network]
allow = ["proxy.corp.example.com"]   # trusted in every project (appended)

[limits]
max_boxes        = 12                 # across ALL projects
max_total_memory = "48g"              # sum of running boxes' limits
on_limit         = "error"            # "error" | "reap-idle"
```

## Matching `.agentignore` files

Config controls the box; `.agentignore` (gitignore syntax, last-match-wins)
controls what the box can *read*. A sensible project default — note `.git`
is deliberately **not** masked (masking it costs diff/commit/history):

```gitignore
# .agentignore — files matched here are unreadable from inside the box
.env
.env.*
!.env.example
*.pem
*.key
id_rsa
id_ed25519
credentials.json
secrets/
```

A user-global `$XDG_CONFIG_HOME/agentbox/agentignore` applies beneath every
project's ignore files, so `*.pem` and `id_rsa` can be masked everywhere
without restatement — and a project can re-include a file with a leading `!`.
Verify what's hidden with `agentbox masks` before running an agent.
