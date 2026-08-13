# Configuration reference

`agentbox.toml` is the project's declarative configuration: committed,
reviewable, and statically validated. This document is the full reference;
`agentbox.toml(5)` is the same material as a man page.

## Layers

Four layers, merged lowest to highest:

| # | Layer | Location |
|---|---|---|
| 1 | built-in defaults | compiled into the binary |
| 2 | user | `$XDG_CONFIG_HOME/agentbox/config.toml` (default `~/.config/agentbox/config.toml`) |
| 3 | workspace | `agentbox.toml` or `.agentbox.toml` in the workspace root |
| 4 | flags | command line |

There is deliberately no system layer, no environment-variable layer, and no
profile layer. Each was one more place a value could come from that nobody
thought to look at; four layers is the whole story, and
`agentbox config --origin` attributes every key to the one that set it.

`-c FILE` replaces the workspace layer with a file of your choosing.
`--no-config` drops layers 2 and 3 entirely, leaving built-in defaults plus
flags.

### Merge semantics

Scalars replace. Tables merge key-wise, so a higher layer setting one key
does not discard its siblings. Arrays **append**, with two escapes:

```toml
bundles = ["!reset", "github"]   # discard everything inherited, then add
bundles = ["!npm"]               # remove an inherited entry
```

### When the workspace layer weakens something

A workspace config is written by whoever wrote the repository, not by the
person about to run an agent in it, and it outranks the user layer. agentbox
lets it win and then says so: any workspace value that *loosens* a ranked
security key relative to a lower layer produces a warning on **every**
invocation, naming the key, both values, and the file.

Ranked keys, loosest value first:

| Key | Order |
|---|---|
| `security.min_isolation` | `container` → `vm` |
| `network.mode` | `open` → `proxy` → `off` |
| `security.mask_mode` | `view` → `auto` → `filter` |
| `security.strip_setuid` | `false` → `true` |
| `workspace.readonly` | `false` → `true` |
| `security.container.read_only_root` | `false` → `true` |
| `security.container.no_new_privileges` | `false` → `true` |
| `security.vm.guest_root` | `allow` → `deny` |

Tightening is silent — a project asking for a stronger box is a project
config doing its job. A flag both overrides the workspace value and clears
the warning, because a flag is typed by the person at the prompt. Only
`security.min_isolation` and `network.mode` have such a flag
(`--min-isolation`, `--network`); for the rest the warning names no flag,
because `--config` replaces the whole workspace layer rather than one key.

`network.allow` and `network.bundles` are **not** ranked: declaring the
registries a project needs is the ordinary case for a project config. Use
`agentbox config --origin` to see where any domain came from.

## Full schema

Every key below is the complete set. Unknown keys are a **hard error**
(exit 78) on every machine — a silently ignored key is a security bug.

```toml
version = 1                      # required; only 1 is supported

[box]
default_command = ["bash", "-l"] # what bare `agentbox` runs
idle_timeout    = "30m"

[workspace]
mount    = "/workspace"          # where the tree appears in the box
readonly = false

[toolchains]                     # preset toolchains layered onto the base image
# dotnet = "10"
# go     = "1.26.5"
# node   = "24"
# python = "3.13"
# rust   = "1.83"

[image]
# Three ways to choose the image, highest precedence first:
#   ref        — a prebuilt OCI image, used verbatim; toolchain keys then ignored
#   dockerfile — a Dockerfile you own, built as-is; toolchain keys then ignored
#   base       — the base image agentbox layers its user/toolchain/agent steps on
# ref        = "ghcr.io/me/box:2026-06"
# dockerfile = "Dockerfile"      # relative to this config file's directory
base         = "ubuntu:26.04"
packages     = []                # extra apt packages for the generated image
# [image.build_args]             # passed to the build as --build-arg

[agents]
install = []                     # e.g. ["claude-code"]; baked into the image
channel = "stable"               # stable | latest
# `agentbox init` scaffolds install = ["claude-code"]. This and the matching
# "agent:*" entry in [network].bundles are a pair: one installs the binary,
# the other opens egress to its endpoints. agentbox warns when they disagree
# and it is generating the image.

[network]
mode    = "proxy"                # off | proxy | open
bundles = []                     # curated allowlist groups
allow   = []                     # extra domains
deny    = []                     # evaluated first, always wins
audit   = true

[network.proxy]
read_timeout    = "1h"           # streamed model responses must not be cut off
request_timeout = "5m"

[resources]
memory     = "8g"
cpus       = 4
pids       = 4096
tmpfs_size = "4g"
nofile     = 65536

# ---- security: neutral keys only ----
[security]
min_isolation = "container"      # container | vm
# backend     = "container"      # pin a backend; never selected below the floor
strip_setuid  = true
mask_mode     = "auto"           # auto | view | filter

# ---- security: container tier ----
[security.container]
read_only_root    = true
no_new_privileges = true
cap_drop          = ["ALL"]
cap_add           = []           # non-empty warns: it weakens the boundary
userns            = "auto"       # auto | keep-id | host | off
seccomp           = "default"

# ---- security: vm tier ----
[security.vm]
guest_root     = "allow"         # allow | deny
nested_docker  = false
memory_backing = "balloon"       # balloon | prealloc

[masking]
ignore_files   = [".agentignore"]
tmpfs_size     = "1m"
files_readonly = true

[variables]                      # environment variables set in the box
# FOO = "bar"
[variables.passthrough]
names = []                       # host variables to forward by name
```

## Notes on specific keys

### Customizing the image

Three mutually exclusive strategies, highest precedence first:

1. **`[image].ref`** — a prebuilt OCI image used verbatim. agentbox builds
   nothing and declared toolchains are ignored (the image must provide
   them); it warns if you set both. `agentbox rm` never deletes an image you
   pinned this way — it reclaims only images it built.
2. **`[image].dockerfile`** — a Dockerfile you own, built as-is. A relative
   path resolves against the directory of the config file that set it, so a
   baseline Dockerfile kept beside your user config resolves the same way
   from every project. The build context contains only the Dockerfile, so it
   must be self-contained: install via `RUN`, not `COPY` from the host.
3. **`[image].base` + `[toolchains]` + `[image].packages`** — the default.
   agentbox generates a Dockerfile from the declared features and tags it by
   a digest of those features, so identical configuration across projects
   reuses one image and a change to any feature produces a new tag.

Toolchain versions install pinned; a value of `"none"` excludes a toolchain
that a lower layer enabled.

### `security.min_isolation`

The weakest tier the project accepts. If no available backend meets it,
agentbox exits **69** naming what is missing rather than running somewhere
weaker.

`--min-isolation` may raise the floor for one invocation but never lower it.
Lowering requires `--force-isolation TIER`, which is recorded in the box's
metadata and warned about on **every** subsequent invocation.

### `security.mask_mode`

| Mode | Behavior |
|---|---|
| `view` | Masks are materialized as mounts when the box is created. Files matching later do not become masked until the box is recreated. |
| `filter` | Patterns are evaluated at lookup time by agentbox's own FUSE share, so a secret created *after* the box starts is hidden immediately. vm tier only. |
| `auto` | `filter` where it can be delivered, otherwise `view` **with a warning naming the reason**. |

`filter` needs the vm tier, `/dev/fuse`, and a mount route: agentbox running
as root, or setuid `fusermount3` with `user_allow_other` in `/etc/fuse.conf`.
Requesting `filter` where it cannot be delivered is a configuration error,
never a silent downgrade to `view`.

### `network.mode`

| Mode | Behavior |
|---|---|
| `off` | No egress path exists. The box network is `--internal`, so there is no route off the bridge and no proxy. |
| `proxy` | Default deny. The box has no route out; the only path is a squid sidecar enforcing the allowlist, with an audit trail. |
| `open` | Ordinary network access. The allowlist and audit trail do not apply, and agentbox warns on every invocation. |

Under `proxy`, the guest needs no DNS resolver of its own — the proxy
resolves on its behalf, which also denies the box a DNS side channel.

### Backend-scoped keys

Keys under `[security.container]` and `[security.vm]` are validated
**statically on every machine**, whether or not that backend is in use.
Putting `cap_drop` under `[security.vm]`, or `nested_docker` under
`[security.container]`, is an error naming where the key belongs. This is
deliberate: a config that is only wrong on someone else's laptop is worse
than one that is wrong everywhere.

### Mask patterns (`.agentignore`)

gitignore syntax, matched by the same engine and differentially tested
against `git check-ignore`. Patterns come from `$XDG_CONFIG_HOME/agentbox/agentignore`
and every file named in `[masking].ignore_files`, in that order.

A masked file is not readable from the box, and writes to it never reach the
host. Under `filter` mode a masked path does not appear in directory
listings at all.

`.git` is deliberately absent from the scaffolded patterns: masking it would
break every tool the agent needs.

`--no-mask` disables masking for one invocation and warns loudly. There is
no configuration key for it: turning masking off should require saying so at
the prompt, every time.
