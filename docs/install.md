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
- [Shell completions](#shell-completions)
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
| **`git`** | Required for the `worktree` and `copy` tree modes, and used by `agentbox doctor` to inspect remotes. The ignore-matcher is also differentially tested against `git check-ignore`. |
| **To build** | Go ≥ 1.22 to compile; the repo's toolchain is pinned to Go 1.26 in `go.mod`. |

None of the runtimes is a hard dependency of the *binary* — building
agentbox on a machine with no runtime succeeds, and `agentbox doctor` then
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
installs. It does **not** install shell completions — generate those
separately (see [completions](#shell-completions)).

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
  virtualization enabled. `agentbox doctor` reports whether it's there.
- **Kata Containers** driven through Docker (runtimes `kata`, `kata-qemu`,
  `kata-clh`). See [libkrun is not usable](#libkrun-is-not-usable) for why
  it is the only supported option.
- **`CAP_SYS_ADMIN`** for agentbox itself, so it can construct the host-side
  mask view. Without it, mask mounts are expressed *inside* the guest and
  agentbox **warns** that a guest-root process could unmount them — no
  silent weakening, but a real caveat.

`agentbox doctor` and `agentbox backends` list every engine/runtime pair
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

`agentbox doctor` reports which route is available and which way `auto`
resolves. Note that the **host-side `view`** (Layer 0/2 mounts) still needs
CAP_SYS_ADMIN — there is no unprivileged equivalent, so a non-root agentbox
using `view` expresses mask mounts in the guest and warns. Under the vm tier
the rootless path is therefore `filter`, which is also the stronger mode.

Follow the upstream install docs for
[Kata Containers](https://katacontainers.io/); then confirm with
`agentbox doctor`, which lists each backend, its tier, and whether it's
available.

#### libkrun is not usable

[libkrun](https://github.com/containers/libkrun), driven through Podman as
the `krun` OCI runtime, looks like a natural second option for this tier and
is **not** one. Every agentbox operation on a box is an engine `exec`: the
box is created running `sleep infinity`, and `up`, `run` and `shell` all
enter it. crun's libkrun handler implements no `exec` callback — libkrun
boots a microVM whose init *is* the entrypoint, with no in-guest agent to
spawn further processes — so a box created under `krun` starts and then
refuses every command with "the handler does not support exec"
([containers/crun#2090](https://github.com/containers/crun/issues/2090)).
Kata works because `kata-agent` and its shim implement exec over vsock.

What agentbox does about it:

- `krun` is never selected by `auto`, on either engine. If the binary is
  installed, `agentbox doctor` names it and explains why it is not a
  candidate, rather than reporting that no VM runtime was found.
- `runtime = "krun"` or `hypervisor = "libkrun"` is a configuration error
  (exit 78) naming the exec limitation and pointing here. The values remain
  valid schema so that this is the message you get.
- If krun is the only VM runtime on the host, the `vm` tier is unavailable
  and `min_isolation = "vm"` exits 69. Install Kata, or lower the floor
  deliberately with `--force-isolation container` — which is recorded in the
  box's metadata and warned about on every invocation.

## Shell completions

A source build doesn't place completions; generate them from the binary:

```console
$ agentbox completion bash | sudo tee /usr/share/bash-completion/completions/agentbox >/dev/null
$ agentbox completion zsh  | sudo tee /usr/share/zsh/site-functions/_agentbox        >/dev/null
$ agentbox completion fish > ~/.config/fish/completions/agentbox.fish
```

Or, from a source checkout, `make completions` writes all three into
`completions/`.

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
$ agentbox doctor
```

`agentbox doctor` is the preflight check and the single best signal that the
install is usable. In a project directory it reports:

- the resolved **workspace and project** identity;
- **configuration** validity and the layers that merged;
- **workspace trust** — whether a committed config declaring `[hooks]` or
  `[[workspace.mounts]]` has been reviewed and trusted;
- each **backend**, its tier, and whether it's available (and if not, why);
- whether **`/dev/kvm`** is present (for the vm tier);
- **git remotes** that use SSH — a warning, since proxy-mode egress carries
  HTTPS, not SSH;
- whether `.git` is accidentally masked;
- the **network** policy and whether its allowlist is empty.

It exits non-zero if it finds issues, so it's safe to gate scripts on.
`doctor` is one of the read-only commands that runs even against an untrusted
workspace config, so you can review a freshly cloned repo before trusting it.

## First run

```console
$ cd ~/src/myapp
$ agentbox init                  # scaffold agentbox.toml + .agentignore
$ agentbox doctor                # preflight
$ agentbox --dry-run claude      # print the full plan; create/start nothing
$ agentbox mounts                # what will the agent see, and why?
$ agentbox claude                # run the agent in the box
```

If the repo ships a committed `agentbox.toml` with `[hooks]` or
`[[workspace.mounts]]`, agentbox **refuses to run it (exit 77)** until you
review the file and run `agentbox trust` — committed config is untrusted by
default, and any edit re-arms the check. See
[docs/configuration.md](configuration.md) for the full config reference.

## Upgrading

`git pull` in your checkout, then `make install` (or `go build`) again.
agentbox is pre-1.0 and the config schema may still change; egress-bundle
changes are listed in `CHANGELOG.md` because they widen policy for everyone
using that bundle, so read it before upgrading.

## Uninstalling

```console
# matching your install PREFIX
$ sudo rm /usr/local/bin/agentbox \
          /usr/local/share/man/man1/agentbox.1 \
          /usr/local/share/man/man5/agentbox.toml.5 \
          /usr/local/share/man/man7/agentbox-security.7
```

agentbox keeps per-project and per-box state under
`$XDG_STATE_HOME/agentbox` (defaults to `~/.local/state/agentbox`). Remove
boxes cleanly with `agentbox rm` / `agentbox prune` **before** uninstalling
so their containers/worktrees are torn down; then delete the state directory
if you want no trace left.

## Troubleshooting

| Symptom | Cause & fix |
|---|---|
| `exit 69`, "isolation floor unsatisfiable" | No available backend meets `min_isolation`. Run `agentbox doctor` / `agentbox backends`; install or fix the runtime for that tier, or lower the floor deliberately with `--force-isolation` (recorded in box metadata and warned every run). |
| `exit 77`, config refused | The committed workspace config declares `[hooks]` or `[[workspace.mounts]]` and isn't trusted. Review the file, then `agentbox trust`. |
| `exit 78`, invalid config | Static validation failed — an unknown key, or a backend-scoped key in the wrong section (`[security.container]` vs `[security.vm]`). These are hard errors on every machine. Run `agentbox config --origin` to see where each key came from. |
| `exit 64`, usage error | Bad flags or an unknown subcommand. |
| `agentbox doctor` warns the vm mask view is guest-side | agentbox lacks `CAP_SYS_ADMIN`. Grant it so the mask view is constructed host-side; otherwise a guest-root process could unmount it. |
| Git operations fail inside the box | Proxy-mode egress carries HTTPS, not SSH. Switch the remote to an HTTPS URL, or add the needed host to the network allowlist. `agentbox logs --denied` shows what was refused. |
| `docker compose` not found | You have the old `docker-compose` v1; agentbox needs Compose v2 (the `docker compose` subcommand). Install `docker-compose-v2`, or use rootless Podman. |

agentbox writes all diagnostics to **stderr**; **stdout belongs to the
in-box command**, and the in-box command's exit code is passed through
verbatim (except for agentbox's own `sysexits.h` codes above). That makes it
safe to pipe agent output while still seeing agentbox's own messages.

## See also

- [README.md](../README.md) — overview and quickstart
- [docs/configuration.md](configuration.md) — full config reference
- [docs/security.md](security.md) — threat model and property table
- `agentbox(1)`, `agentbox.toml(5)`, `agentbox-security(7)` — man pages
