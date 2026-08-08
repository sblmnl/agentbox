# Configuration reference

The same material ships as `agentbox.toml(5)`. This page is the
authoritative reference for the configuration schema.

## Layers

Lowest to highest precedence:

1. Built-in defaults, compiled in
2. `/etc/agentbox/config.toml`
3. `$XDG_CONFIG_HOME/agentbox/config.toml`
4. Workspace `agentbox.toml` (or `.agentbox.toml`; both present is an error)
5. Profile overlay named by `--profile`, `AGENTBOX_PROFILE`, or `[box].profile`
6. `AGENTBOX_*` environment variables (`AGENTBOX_NETWORK__MODE=none` sets `network.mode`)
7. Command-line flags

Exactly one workspace file participates — the one at the workspace root. A
monorepo subdirectory wanting different settings should use a profile. A
file may set `extends = "PATH"` to include another file as a
lower-precedence layer (cycles are detected).

**Merge semantics:** scalars and tables — higher layer replaces. Arrays —
**append**, with two escapes: `"!reset"` as an element discards everything
inherited so far for that key; `"!value"` removes `value` if inherited.
Append is the right default because the common case is a project adding one
internal registry to inherited defaults, not restating them.

`agentbox config --origin` reports, per key, the layer that supplied the
final value. Layered configuration without that is undebuggable.

**Unknown keys are a hard error.** A silently ignored `securiy` block is a
security bug. Backend-specific keys must appear only inside
`[security.container]` or `[security.vm]`; a backend-specific key at a
neutral level is a schema error on **every machine**, regardless of which
backend is active.

## Full schema

```toml
version = 1

[box]
name            = "myapp"        # display only; does not affect any id
profile         = "dotnet"
default_command = ["bash", "-l"]
default_agent   = "claude"
idle_timeout    = "30m"          # stop a box after this long with no exec; "0" disables

[project]
max_boxes = 4                    # refuse to create beyond this; 0 = unlimited

[workspace]
mount     = "/workspace"
readonly  = false
tree_mode = "auto"               # "auto" | "shared" | "worktree" | "copy"

[[workspace.mounts]]             # requires `agentbox trust`; bypasses masking
source = "~/.gitconfig"
target = "/home/agent/.gitconfig"
mode   = "ro"

[toolchains]
dotnet = "10"
node   = "24"
python = "3.13"
go     = "none"
rust   = "none"

[image]
# Three ways to choose the image, highest precedence first:
#   ref        — a prebuilt OCI image, used verbatim; toolchain keys then ignored
#   dockerfile — a Dockerfile you own, built as-is; toolchain keys then ignored
#   base       — the base image agentbox layers its user/toolchain/agent steps on
# ref = "ghcr.io/me/box:2026-06"
# dockerfile = "Dockerfile"       # relative to this config file's directory;
                                  # keep one in $XDG_CONFIG_HOME/agentbox for a
                                  # global baseline toolchain. It must create the
                                  # agent user from the AGENTBOX_UID/AGENTBOX_GID
                                  # build args agentbox passes in.
base       = "ubuntu:26.04"       # or any OCI ref, e.g. a toolchain image you built
packages   = ["postgresql-client", "graphviz"]
build_args = { TZ = "UTC" }

[agents]
install = ["claude-code"]
channel = "stable"

[network]
mode    = "proxy"                # "none" | "proxy" | "open"
bundles = ["agent:claude-code", "github", "npm", "pypi", "nuget"]
allow   = ["registry.internal.example.com"]
deny    = []
audit   = true

[network.proxy]
read_timeout    = "1h"           # long enough for streamed model responses
request_timeout = "5m"

[resources]
memory     = "8g"
cpus       = 4
pids       = 4096
tmpfs_size = "4g"
nofile     = 65536

# ---- security: neutral keys only ----
[security]
min_isolation = "container"      # "container" | "vm"
strip_setuid  = true             # image build property, tier-independent
mask_mode     = "auto"           # "auto" | "view" | "filter"

# ---- security: container tier ----
[security.container]
read_only_root    = true
no_new_privileges = true
cap_drop          = ["ALL"]
cap_add           = []           # non-empty warns
userns            = "auto"       # "auto" | "keep-id" | "host" | "off"
seccomp           = "default"
guest_root        = "deny"       # "deny" only; "allow" here is a parse error

# ---- security: vm tier ----
[security.vm]
hypervisor     = "auto"          # "auto" | "qemu" | "cloud-hypervisor" | "libkrun"*
runtime        = "auto"          # "auto" | "kata" | "krun"*
                                 # * accepted values, then refused: libkrun cannot
                                 #   serve this tier (crun implements no exec, so
                                 #   nothing can enter the box) — see docs/install.md
guest_root     = "allow"         # "allow" | "deny"
nested_docker  = false           # safe only under this tier
memory_backing = "balloon"       # "balloon" | "prealloc"

[masking]
ignore_files   = [".agentignore"]
tmpfs_size     = "1m"
files_readonly = true

[variables]
TZ = "UTC"

[variables.passthrough]
names = ["ANTHROPIC_API_KEY", "GH_TOKEN"]

[hooks]                          # requires `agentbox trust`; run on the HOST
pre_up   = []
post_up  = []
pre_exec = []

[profiles.airgapped]
[profiles.airgapped.network]
mode = "none"
```

User- or system-level configuration may additionally set cross-project
limits (these belong outside the project file):

```toml
# $XDG_CONFIG_HOME/agentbox/config.toml
[limits]
max_boxes        = 12            # across all projects
max_total_memory = "48g"         # sum of running boxes' limits
on_limit         = "error"       # "error" | "reap-idle"
```

## Notes on specific keys

### Customizing the image

There are **three ways to decide what image a box runs**, in strict
precedence order. Higher wins, and choosing a higher one turns off the
machinery below it:

1. **`image.ref`** — a prebuilt OCI image, used **verbatim**. agentbox adds
   no layers. `[toolchains]`, `image.base`, `image.packages`, and
   `image.build_args` are then ignored; the referenced image must already
   provide everything (including an `agent` user matching your uid). This is
   the "you own the image" path — reproducible, and the right choice for
   air-gapped or golden-image workflows.
2. **`image.dockerfile`** — a Dockerfile *you* own, built **as-is** (path is
   relative to the config file's directory; put one in
   `$XDG_CONFIG_HOME/agentbox` for a global baseline). Declared toolchains
   are ignored — your Dockerfile installs them. Your Dockerfile **must**
   honor the build-arg contract below.
3. **Generated** (the default) — agentbox generates a Dockerfile from
   `image.base` + `[toolchains]` + `image.packages` + `[agents]`, layering in
   a non-root `agent` user, toolchain installs (preferring the distro
   archive; where a third-party apt repo is genuinely required its signing
   key is pinned by fingerprint and the build fails on mismatch, never
   fetch-and-trust), the agent, and — when `security.strip_setuid` is
   set — a filesystem-wide setuid/setgid strip. This is the zero-Dockerfile
   path: declare `node = "24"` and get a working image.

**No silent surprises.** Setting `ref` or `dockerfile` while also declaring
toolchains is honored, but **warned**: agentbox tells you the *N* declared
toolchains are being ignored because you took ownership of the image.
Setting both `ref` and `dockerfile` warns that `ref` wins and the Dockerfile
is unused. These warnings are part of the contract, not noise.

**Editing the image triggers a rebuild automatically.** The generated tag is
a *feature digest* — `sha256` over `base`, toolchains, `packages`, `agents`,
and `build_args`. Change any of them and the tag changes, so the next
invocation rebuilds; leave them alone and the cached image is reused. A
user-supplied `dockerfile` is digested by its **contents**, so editing the
file forces a rebuild the same way. `agentbox build` forces a rebuild
explicitly; `agentbox --dry-run <cmd>` and `agentbox config` show the
resolved reference and whether it will be built locally or pulled.

**Build-arg contract (paths 2 and 3).** agentbox passes three build args in;
a custom Dockerfile **must** consume the first two or uid mapping and mask
ownership break:

| Build arg | Meaning |
|---|---|
| `AGENTBOX_UID` / `AGENTBOX_GID` | The invoking user's uid/gid. Create the `agent` user with exactly these (reclaiming any existing uid the base image ships, e.g. Ubuntu's `ubuntu` at 1000) so files the agent writes are owned by *you* on the host and masks line up. |
| `AGENTBOX_GUEST_ROOT` | `allow` or `deny` (from the active tier's `guest_root`). When `allow`, install `sudo` for the agent; when `deny`, ensure it is absent. This is the one image property that varies by tier, so it is a build arg — the feature digest stays backend-independent. |

`image.build_args` entries become additional `ARG` lines (and, being part of
the digest, correctly force a rebuild when changed). `image.packages` are
extra apt packages layered on top of agentbox's baseline agent toolset
(`git`, `ripgrep`, `fd`, `jq`, `curl`, `tmux`, `sqlite3`, …). `[agents]`
selects which agent is baked in (`install`) and its release channel
(`channel = "stable"` or `"latest"`); no credentials are ever written into
any layer.

### `security.min_isolation`

Declares the weakest isolation tier the project accepts. When no available
backend meets it, agentbox exits 69 naming what is missing (no KVM device,
no runtime binary). Silent downgrade never occurs, and neither does warned
downgrade — a warning that scrolls past is not consent. Lowering requires
`--force-isolation`, which is recorded, surfaced by `status` and `ls`, and
warned about on every invocation of the resulting box.

### `workspace.tree_mode`

How concurrent boxes obtain a working tree. Two boxes mounting one host
directory read-write will overwrite each other's edits, and the corruption
presents as inexplicable behavior rather than a conflict.

| Mode | Behavior |
|---|---|
| `shared` | The box mounts the workspace directly. Edits appear on the host immediately. |
| `worktree` | The box gets its own `git worktree` on its own `agentbox/<instance>` branch, kept under the state directory so `git status` stays clean. |
| `copy` | The box gets a private copy. For non-git workspaces. |
| `auto` | `shared` for the first box; `worktree` for each additional box in a git workspace, else `copy`. |

`rm` removes a box's worktree but preserves its branch unless
`--delete-branch` is passed: unreviewed agent work is the most valuable
thing in the box and the easiest to destroy by accident.

### `security.mask_mode`

- `view` — host-side mount masking. Available under both tiers. Masked
  files read empty; masked directories appear empty. Fixed at creation.
- `filter` — lookup-time filtering in agentbox's own share daemon. `vm`
  tier only; requesting it under `container` is an error, not a downgrade.
  Masked paths answer `ENOENT` and are omitted from listings; the filter
  is evaluated live, so files created mid-session are masked too, and
  masked directories impose no tmpfs size cap. Needs `/dev/fuse` plus one
  of two mount routes: agentbox running as root, or — fully in the user's
  context — the setuid `fusermount3` helper with `user_allow_other` set in
  `/etc/fuse.conf`. Requesting it where neither route exists is an error
  naming what would fix it.
- `auto` — `filter` where available, else `view`. Under the `vm` tier with
  the seam available (root + `/dev/fuse`) that is `filter`; anywhere else
  `view`, and the vm-tier fallback is announced, never silent.
  `agentbox doctor` reports which way `auto` resolves on this host, and
  `status`/`masks` report the mode in force.

### Backend-scoped keys

`guest_root = "allow"` exists only under `[security.vm]`, because under the
container tier it would silently void masking. `nested_docker` likewise
exists only under `vm`. `cap_drop` has no meaning to a hypervisor and is
absent from `[security.vm]`. Writing any of them in the wrong scope is a
parse error everywhere — the point is that a config authored on a laptop
fails identically on a colleague's machine instead of silently weakening.

### Mask patterns (`.agentignore`)

Syntax matches `.gitignore` exactly: `#` comments, `!` negation with
last-match-wins, trailing `/` for directories, leading or embedded `/`
anchors to the workspace root, `*`/`?` not crossing `/` while `**` does,
`[...]` classes. The matcher is differentially tested against
`git check-ignore`.

A user-global `$XDG_CONFIG_HOME/agentbox/agentignore` applies below the
workspace's ignore files, so `*.pem` and `id_rsa` can be masked in every
project without restatement, and later layers can re-include with `!`.

### Hooks and trust

`[hooks]` commands run **on the host** (`pre_up`, `post_up`, `pre_exec`),
and `[[workspace.mounts]]` exposes host paths to the guest. Because the
workspace config is committed, both are refused from a config you have not
explicitly trusted: review the file, then run `agentbox trust`. Any edit
invalidates the record. `agentbox trust --show` prints the current status;
`doctor` includes it in preflight.
