# Configuration examples

Copy-paste starting points. Every key here is documented in
[configuration.md](configuration.md) / `agentbox.toml(5)`; this file is
about *shapes* of real projects, not the schema.

All of them assume `version = 1` and that the file is `agentbox.toml` in the
workspace root. Check what any of them actually resolves to with:

```console
$ agentbox config --origin      # every key, and the layer that set it
$ agentbox --dry-run --json     # the full plan: masks, egress, backend, image
```

## Contents

- [Minimal starter](#minimal-starter)
- [Node / TypeScript web app](#node--typescript-web-app)
- [Python data project](#python-data-project)
- [Go service](#go-service)
- [.NET project](#net-project)
- [Air-gapped / offline](#air-gapped--offline)
- [Hardened VM tier](#hardened-vm-tier)
- [Private registry](#private-registry)
- [Prebuilt or custom image](#prebuilt-or-custom-image)
- [Parallel boxes](#parallel-boxes)
- [User-global config](#user-global-config)
- [Matching `.agentignore` files](#matching-agentignore-files)

## Minimal starter

What `agentbox init` scaffolds: Claude Code installed, default-deny egress
with just its own endpoints and GitHub.

```toml
version = 1

[agents]
install = ["claude-code"]
channel = "stable"

[network]
mode    = "proxy"
bundles = ["agent:claude-code", "github"]
allow   = []

[security]
min_isolation = "container"
```

`[agents].install` and the `agent:*` entry in `[network].bundles` are a pair:
the first puts the binary in the image, the second lets it reach its own
endpoints. Keeping one without the other gives you a box that either cannot
run the agent or cannot let it talk, so agentbox warns when they disagree —
unless you pin `[image].ref` or supply your own Dockerfile, where the agent
may perfectly well already be present.

Not using Claude Code? Delete both lines together.

## Node / TypeScript web app

```toml
version = 1

[toolchains]
node = "24"

[network]
mode    = "proxy"
bundles = ["agent:claude-code", "github", "npm"]
allow   = ["registry.company.example"]

[resources]
memory = "8g"
cpus   = 4

[security]
min_isolation = "container"
```

Note the trap in [`configuration.md`](configuration.md#mask-patterns-agentignore):
do **not** mask `node_modules/` under `mask_mode = "view"`. A masked
directory is a small writable ramdisk there, and the first `npm install`
fills it. Under `filter` mode a masked directory simply does not exist, so
the failure is different but still unhelpful — there is no reason to mask it
either way.

## Python data project

```toml
version = 1

[toolchains]
python = "3.13"

[image]
packages = ["build-essential", "libpq-dev"]

[network]
mode    = "proxy"
bundles = ["agent:claude-code", "github", "pypi"]

[resources]
memory = "16g"          # notebooks and dataframes are hungry
cpus   = 8
```

## Go service

```toml
version = 1

[toolchains]
go = "1.26.5"           # keep in step with the `go` directive in go.mod

[network]
mode    = "proxy"
bundles = ["agent:claude-code", "github", "go"]

[security]
min_isolation = "container"
```

`GOTOOLCHAIN=local` is set in the generated image, so a `go` directive newer
than the installed toolchain fails loudly instead of silently downloading a
different compiler through the proxy.

## .NET project

```toml
version = 1

[toolchains]
dotnet = "10"

[network]
mode    = "proxy"
bundles = ["agent:claude-code", "github", "nuget"]
```

## Air-gapped / offline

No egress path exists at all: the box network is `--internal`, and no proxy
is created. Use a prebuilt image so nothing needs fetching at build time.

```toml
version = 1

[image]
ref = "registry.internal.example/agentbox/base:2026-06"

[network]
mode = "off"

[security]
min_isolation = "vm"
```

`agentbox rm` will not delete that image: it is pinned with `[image].ref`, so
agentbox did not build it and does not reclaim it.

## Hardened VM tier

Everything the vm tier can be asked to tighten.

```toml
version = 1

[security]
min_isolation = "vm"
mask_mode     = "filter"   # lookup-time filtering; hides files created later
strip_setuid  = true

[security.vm]
guest_root     = "deny"
nested_docker  = false
memory_backing = "prealloc"

[workspace]
readonly = false           # set true for review-only boxes

[network]
mode    = "proxy"
bundles = ["agent:claude-code", "github"]
audit   = true
```

`mask_mode = "filter"` requires the vm tier, `/dev/fuse`, and a mount route
(agentbox as root, or setuid `fusermount3` with `user_allow_other`). If it
cannot be delivered, this is an **error** — never a quiet fallback to
`view`. Use `"auto"` if you would rather have the fallback, which then warns
and names the reason.

## Private registry

```toml
version = 1

[image]
base = "registry.internal.example/base/ubuntu:26.04"

[toolchains]
node = "24"

[network]
mode    = "proxy"
bundles = ["agent:claude-code", "github"]
allow   = [
    "registry.internal.example",
    "artifacts.internal.example",
]

[image.build_args]
NPM_CONFIG_REGISTRY = "https://artifacts.internal.example/npm/"
```

If the registry needs a credential, keep it out of the tree and forward it
by name:

```toml
[variables.passthrough]
names = ["NPM_TOKEN"]
```

## Prebuilt or custom image

Three mutually exclusive strategies, highest precedence first.

**A prebuilt image, used verbatim.** Declared toolchains are ignored — the
image must provide them — and agentbox warns if you set both.

```toml
version = 1

[image]
ref = "ghcr.io/me/agentbox-base:2026-06"
```

**A Dockerfile you own, built as-is.** A relative path resolves against the
directory of the config file that set it. The build context contains only
the Dockerfile, so it must be self-contained: install with `RUN`, not `COPY`
from the host.

```toml
version = 1

[image]
dockerfile = "docker/agentbox.Dockerfile"

[image.build_args]
VARIANT = "full"
```

The image must provide a user matching your uid/gid; agentbox passes
`AGENTBOX_UID` and `AGENTBOX_GID` as build args for exactly this.

**The generated Dockerfile** (the default) — declare features and let
agentbox build. The tag is a digest of the declared features, so identical
configuration across projects reuses one image and any feature change
produces a new tag.

```toml
version = 1

[image]
base     = "ubuntu:26.04"
packages = ["graphviz", "postgresql-client"]

[toolchains]
node   = "24"
python = "3.13"
```

## Parallel boxes

There is no configuration for this, and that is the point. A box is
identified by its workspace root, so a second root is a second box:

```console
$ git worktree add ../myapp-feature feature/thing
$ cd ../myapp-feature
$ agentbox claude
```

That box has its own container, its own network, its own persistent home,
its own mask view, and — because it is a git worktree — its own branch and
its own checkout. Nothing is shared, and nothing had to be configured.

The committed `agentbox.toml` comes along with the worktree, so both boxes
get the same policy without duplication.

## User-global config

`$XDG_CONFIG_HOME/agentbox/config.toml` (default
`~/.config/agentbox/config.toml`) applies to every project. It sits *below*
the workspace layer, so a project can override it — and agentbox warns on
every invocation when a project overrides one of these in the loosening
direction.

```toml
# ~/.config/agentbox/config.toml
[security]
min_isolation = "vm"        # my machine has KVM; hold the line by default

[network]
bundles = ["agent:claude-code"]   # every project gets the agent's endpoints

[resources]
memory = "16g"

[variables.passthrough]
names = ["GH_TOKEN"]
```

A user-global `.agentignore` lives beside it at
`$XDG_CONFIG_HOME/agentbox/agentignore` and applies to every project — the
right place for patterns like `*.pem` that you never want visible anywhere.

## Matching `.agentignore` files

gitignore syntax, matched by the same engine and differentially tested
against `git check-ignore`.

```gitignore
# secrets
.env
.env.*
!.env.example
*.pem
*.key
id_rsa
id_ed25519
credentials.json
secrets/

# local state that isn't the agent's business
.terraform/
*.tfstate
*.tfstate.backup
```

Two rules worth internalizing:

- **Do not mask `.git/`.** It costs diff, commit and history for almost no
  gain, which is why the scaffolded file leaves it out.
- **Do not mask build directories** (`node_modules/`, `.venv/`, `obj/`,
  `target/`). Under `view` mode they become small ramdisks that fill; under
  `filter` mode they vanish and the build fails differently. Neither is what
  you want.

Confirm what actually got masked before trusting it:

```console
$ agentbox --dry-run --json | jq '.masks.entries[].path'
```
