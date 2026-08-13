# Installing agentbox

agentbox is a single static Linux binary with one build dependency
(`BurntSushi/toml`). Building it is quick; the part that takes thought is
the **runtime** — agentbox itself runs nothing until it can hand your agent
to a container or VM backend. This guide covers both.

> **Status note.** agentbox is an experimental, educational project (see
> [docs/security.md](security.md)) — not an audited security tool. Nothing is
> published: there are no tags, tarballs, distro packages, or `go install`
> support, and none are planned right now. **The only way to install agentbox
> is to build it from source**, described below.

## Contents

- [Requirements](#requirements)
- [Build from source](#build-from-source)
- [Runtime setup](#runtime-setup)
  - [Container tier](#container-tier-docker-or-rootless-podman)
  - [VM tier](#vm-tier-kata-containers)
- [Man pages](#man-pages)
- [Verify the install](#verify-the-install)
- [First run](#first-run)
- [Upgrading](#upgrading)
- [Uninstalling](#uninstalling)
- [Troubleshooting](#troubleshooting)

## Requirements

| | Requirement |
|---|---|
| **OS** | Linux (`amd64` or `arm64`). agentbox targets Linux only — it drives Linux container/VM runtimes and uses Linux mount namespaces for masking. |
| **Runtime** (one of) | Docker with Compose v2, **or** rootless Podman — for the `container` tier. Kata Containers via docker, on KVM — for the `vm` tier. See [Runtime setup](#runtime-setup). |
| **`git`** | Used for workspace-root detection, and the ignore-matcher is differentially tested against `git check-ignore`. |
| **To build** | Go ≥ 1.22 to compile; the repo's toolchain is pinned to Go 1.26 in `go.mod`. |

None of the runtimes is a hard dependency of the *binary* — building
agentbox on a machine with no runtime succeeds, and `agentbox version` then
tells you what's missing. This is deliberate: putting agentbox on a cloud VM
must not drag in a hypervisor stack it can't use.

## Build from source

```console
$ git clone https://github.com/sblmnl/agentbox
$ cd agentbox
$ make all            # fmt-check + vet + build + test — the pre-PR gate
```

`make all` produces the `agentbox` binary in the repo root. To install it
system-wide together with the man pages:

```console
$ sudo make install                       # PREFIX defaults to /usr/local
$ make install PREFIX="$HOME/.local"      # or a prefix you own, no sudo
```

`make install` places the binary at `$(PREFIX)/bin/agentbox` and the three
man pages under `$(PREFIX)/share/man/`. It honors `DESTDIR` for staged
installs.

A plain `go build` also works if you only want the binary:

```console
$ go build -trimpath ./cmd/agentbox
```

## Runtime setup

agentbox selects a backend that meets your project's declared isolation
floor (`security.min_isolation`, default `container`). You need at least one
working runtime for the tier your projects require. If nothing meets the
floor, agentbox exits **69** naming exactly what is missing — it never
silently downgrades.

### Container tier (Docker or rootless Podman)

Either engine works; agentbox picks whichever is available.

**Docker** (needs Compose v2, i.e. the `docker compose` subcommand):

```console
$ sudo apt install docker.io docker-compose-v2   # Debian/Ubuntu, e.g.
$ sudo usermod -aG docker "$USER"                # then log out and back in
$ docker compose version                         # confirm Compose v2
```

**Rootless Podman** (no daemon, no root — often the better fit):

```console
$ sudo apt install podman
$ podman info                                    # confirm rootless works
```

Universal refusals apply on this tier regardless of engine: no host
networking, no host PID namespace, no mounted runtime socket, no unconfined
seccomp. The container tier protects against a careless or prompt-injected
agent and malicious install scripts, but **not** against a kernel or runtime
escape — see [docs/security.md](security.md) for the full threat model.

### VM tier (Kata Containers)

Choose this tier (`min_isolation = "vm"`) when you want a hypervisor
boundary rather than a shared kernel. It needs:

- **KVM**: `/dev/kvm` present — bare metal, or a VM with nested
  virtualization enabled. `agentbox version` reports whether the tier is available.
- **Kata Containers** driven through Docker (runtimes `kata`, `kata-qemu`,
  `kata-clh`). See [why Docker only](#why-docker-only-for-this-tier) for why
  it is the only supported option.
- **`CAP_SYS_ADMIN`** for agentbox itself, so it can construct the host-side
  mask view. Without it, mask mounts are expressed *inside* the guest and
  agentbox **warns** that a guest-root process could unmount them — no
  silent weakening, but a real caveat.

`agentbox version` lists every backend
found. Where a host has more than one, `runtime = "auto"` takes the first in
preference order (`kata`, `kata-qemu`, `kata-clh`; docker before podman);
set `[security.vm].runtime` or `.hypervisor` explicitly to pin another. A
pinned runtime that no engine provides is an error naming what each one
offers, never a silent fallback.

Both backends consume the **same OCI image** the container tier builds; only
the runtime differs. Under the vm tier, `mask_mode = "auto"` resolves to the
Layer-3 filtered share (`filter`) when agentbox can deliver it, and
otherwise falls back to `view` with a warning; an explicit `"filter"` that
cannot be delivered is a config error.

#### Running the filtered share without root

`filter` needs `/dev/fuse` and a way to mount it. Root mounts it directly,
but the share daemon can also run **entirely in your user's context** via
the setuid `fusermount3` helper. For that route:

- Install **fuse3** (`fusermount3` on `PATH`).
- Enable **`user_allow_other`** in `/etc/fuse.conf` — add a line reading
  exactly `user_allow_other`, on a line by itself:

  ```console
  echo user_allow_other | sudo tee -a /etc/fuse.conf
  ```

  This is a one-time root edit; nothing about running agentbox afterwards
  needs privilege. It is required because the mount is owned by your uid
  while the runtime's virtiofs server may run as another — a root Docker
  daemon's does — and without `allow_other` the kernel refuses it access to
  the share. agentbox requires the option even where the virtiofs server
  happens to share your uid, because the alternative is a box that starts and
  then fails opaquely.

`agentbox status` reports which route is available and which way `auto`
resolves. Note that the **host-side `view`** (Layer 0/2 mounts) still needs
CAP_SYS_ADMIN — there is no unprivileged equivalent, so a non-root agentbox
using `view` expresses mask mounts in the guest and warns. Under the vm tier
the rootless path is therefore `filter`, which is also the stronger mode.

Follow the upstream install docs for
[Kata Containers](https://katacontainers.io/); then confirm with
`agentbox version`, which lists each backend, its tier, and whether it's
available.

#### Why Docker only for this tier

Podman looks like a natural second option here and is **not** one. Its VM
path is [libkrun](https://github.com/containers/libkrun), driven as the
`krun` OCI runtime, and every agentbox operation on a box is an engine
`exec`: the box is created running `sleep infinity`, and `up`, `run` and
`shell` all enter it. crun's libkrun handler implements no `exec` callback —
libkrun boots a microVM whose init *is* the entrypoint, with no in-guest
agent to spawn further processes — so a box created under `krun` starts and
then refuses every command with "the handler does not support exec"
([containers/crun#2090](https://github.com/containers/crun/issues/2090)).
Kata works because `kata-agent` and its shim implement exec over vsock.

So agentbox does not offer it. There is no `runtime` or `hypervisor`
configuration key at all: a value that parses, selects, creates a box and
then cannot be entered is worse than no value. If podman is the only thing
installed, the `vm` tier reports itself unavailable and says why, and
`min_isolation = "vm"` exits 69. Install Docker with a Kata runtime, or
lower the floor deliberately with `--force-isolation container` — which is
recorded in the box's metadata and warned about on every invocation.

Podman support for this tier is wanted; it is blocked upstream, not
declined.

## Man pages

Three man pages ship with agentbox: `agentbox(1)` (the CLI),
`agentbox.toml(5)` (config reference), and `agentbox-security(7)` (the
security model). `make install` installs them; to place them by hand from a
source checkout:

```console
$ sudo install -Dm644 docs/man/agentbox.1          /usr/local/share/man/man1/agentbox.1
$ sudo install -Dm644 docs/man/agentbox.toml.5     /usr/local/share/man/man5/agentbox.toml.5
$ sudo install -Dm644 docs/man/agentbox-security.7 /usr/local/share/man/man7/agentbox-security.7
$ man agentbox
```

## Verify the install

```console
$ agentbox version
```

`agentbox version` lists each backend, its tier, and whether it is available
— and if not, why, with what would fix it.

In a project directory, `agentbox --dry-run` is the preflight check: it
builds the complete plan and changes nothing, so it answers what the agent
would see and reach before anything is created.

```console
$ agentbox --dry-run --json
```

That publishes the resolved backend and tier, the full mask set, the
effective egress allowlist, the image reference, and the guest working
directory. `agentbox config --origin` shows where every key came from, and
`agentbox status` reports an existing box's state and any drift.

## First run

```console
$ cd ~/src/myapp
$ agentbox init                  # scaffold agentbox.toml + .agentignore
$ agentbox --dry-run             # the full plan: masks, egress, backend
$ agentbox claude                # run the agent in the box
```

There is one box per workspace root, so there is nothing to name and nothing
to select: `cd` into the project and you are in its box. For a second box,
make a second root — `git worktree add ../feature` gets its own.

If the repo ships a committed `agentbox.toml` that weakens a security
setting relative to your own configuration, agentbox applies it and warns on
every invocation, naming the key and both values. See
[docs/configuration.md](configuration.md) for the full config reference.

## Upgrading

`git pull` in your checkout, then `make install` (or `go build`) again.
agentbox is pre-1.0 and the config schema may still change. Egress-bundle
changes widen policy for everyone using that bundle, so they are called out
in release notes; read them before upgrading.

## Uninstalling

```console
# matching your install PREFIX
$ sudo rm /usr/local/bin/agentbox \
          /usr/local/share/man/man1/agentbox.1 \
          /usr/local/share/man/man5/agentbox.toml.5 \
          /usr/local/share/man/man7/agentbox-security.7
```

agentbox keeps per-box state under `$XDG_STATE_HOME/agentbox` (defaults to
`~/.local/state/agentbox`). Run `agentbox rm` in each project **before**
uninstalling so its containers, networks, volumes and image are torn down;
then delete the state directory if you want no trace left.

## Troubleshooting

| Symptom | Cause & fix |
|---|---|
| `exit 69`, "isolation floor unsatisfiable" | No available backend meets `min_isolation`. Run `agentbox version` to see why each tier is unavailable; install or fix the runtime for that tier, or lower the floor deliberately with `--force-isolation` (recorded in box metadata and warned every run). |
| `exit 78`, invalid config | Static validation failed — an unknown key, or a backend-scoped key in the wrong section (`[security.container]` vs `[security.vm]`). These are hard errors on every machine. Run `agentbox config --origin` to see where each key came from. |
| `exit 64`, usage error | Bad flags or an unknown subcommand. |
| agentbox warns the vm mask view is guest-side | agentbox lacks `CAP_SYS_ADMIN`. Grant it so the mask view is constructed host-side; otherwise a guest-root process could unmount it. |
| Git operations fail inside the box | Proxy-mode egress carries HTTPS, not SSH. Switch the remote to an HTTPS URL, or add the needed host to the network allowlist. `agentbox logs --denied` shows what was refused. |
| Every network call in a vm box hangs | The proxy sidecar is not answering; agentbox warns about this at start. `agentbox logs --proxy` shows why. |

agentbox writes all diagnostics to **stderr**; **stdout belongs to the
in-box command**, and the in-box command's exit code is passed through
verbatim (except for agentbox's own `sysexits.h` codes above). That makes it
safe to pipe agent output while still seeing agentbox's own messages.

## See also

- [README.md](../README.md) — overview and quickstart
- [docs/configuration.md](configuration.md) — full config reference
- [docs/security.md](security.md) — threat model and property table
- `agentbox(1)`, `agentbox.toml(5)`, `agentbox-security(7)` — man pages
