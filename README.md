# agentbox

> [!WARNING]
> **Experimental — not audited, and not for security-sensitive environments.**
> agentbox has not been independently reviewed, and it is under active
> development. Everything below about isolation, secret masking, and egress
> control describes *design intent*, not a guarantee. Do not rely on agentbox
> to contain untrusted or malicious code, to protect real secrets, or for
> anything where a sandbox escape would actually matter. See
> [docs/security.md](docs/security.md) for the threat model and its limits.

Run an agentic coding tool inside an isolated, per-project environment —
declarative config, default-deny egress, host-side secret masking, one
disposable box per project.

```console
$ cd ~/src/myapp
$ agentbox claude
```

That resolves the workspace root, merges configuration, selects a backend
satisfying the project's declared isolation floor, builds an image matching
the declared toolchains, constructs a masked view of the workspace that
hides secrets, starts a default-deny egress proxy, and execs the agent with
the working directory mapped to match your shell's.

**What this buys you:** the blast radius of an agent mistake is reduced to
one workspace tree and one egress allowlist, both inspectable beforehand
and logged after. That is not the same claim as "safe" — read
[docs/security.md](docs/security.md) before running anything unattended.

## Why

Coding agents want to read your tree, install packages, and talk to the
network. Running them bare means one prompt injection or one confused agent
can read `~/.ssh`, your `.env`, or push to the wrong remote. Running them in
an ad-hoc container means hand-rolling mounts, network rules, and secret
handling per project — and getting it subtly wrong.

agentbox makes the confined path the zero-config path:

- **Zero-setup launch.** Works in any directory; a committed `agentbox.toml`
  makes it reproducible for the whole team.
- **Default-deny egress.** The guest has *no route* to the outside; the only
  path is a proxy enforcing an auditable allowlist. Curated bundles
  (`agent:claude-code`, `github`, `npm`, `pypi`, …) cover the endpoints
  agents actually need; `agentbox logs --denied` shows what was refused.
- **Secret masking, enforced outside the box.** `.agentignore` patterns
  (gitignore syntax, differentially tested against `git check-ignore`) hide
  matched files from the guest — reads return empty, writes never reach the
  host.
- **One box per project directory.** `cd` into a project and you are in its
  box: nothing to name, nothing to list, nothing to pick. Want a second box?
  Make a second directory — `git worktree add ../feature` gets its own box,
  on its own branch, for free.
- **Honest about what it guarantees.** `agentbox status` always names the
  backend, isolation tier, egress mode and mask mode in force, and every
  invocation that starts a box prints the same line.
- **Any agent.** Claude Code is bundled as a first-class citizen, but
  nothing in the data model is vendor-specific.

## Quickstart

```console
$ git clone https://github.com/sblmnl/agentbox && cd agentbox && sudo make install

$ cd ~/src/myapp
$ agentbox init                  # scaffold agentbox.toml + .agentignore
$ agentbox --dry-run             # the full plan: masks, egress, backend
$ agentbox claude                # run your agent in the box
```

Useful from day one:

```console
$ agentbox --dry-run --json      # the plan as JSON: every mask, every allowed domain
$ agentbox config --origin       # every key, annotated with the layer that set it
$ agentbox status                # backend, tier, egress, masking, config drift
$ agentbox logs --denied         # what did the agent try to reach?
$ agentbox down                  # stop and remove the box; keep its home
$ agentbox rm                    # remove the box and everything it holds
```

`down` and `rm` differ in what survives. `down` removes the guest and its
networks but keeps the box's persistent home and identity, so `agentbox`
brings back the same box. `rm` removes all of it — home, state, and the image
agentbox built for it. An image you pinned yourself with `[image].ref` is
never removed: agentbox reclaims only what it made.

Requirements: Linux, Docker or rootless Podman for the container tier,
Docker + a Kata runtime + KVM for the vm tier, `git`, and Go to build. A
single static binary with one dependency (`BurntSushi/toml`). agentbox is
**build-from-source only** — there are no published binaries or packages.
Build steps and runtime setup for each tier are in
[docs/install.md](docs/install.md).

## Configuration

`agentbox.toml` is committed, reviewable, and layered (built-in → user →
workspace → flags), with `config --origin` attribution and static validation
— unknown keys and backend-scoped keys in the wrong place are hard errors on
every machine, not just where they would apply.

```toml
version = 1

[toolchains]
node   = "24"
python = "3.13"

[network]
mode    = "proxy"
bundles = ["agent:claude-code", "github", "npm", "pypi"]
allow   = ["registry.internal.example.com"]

[security]
min_isolation = "container"
```

Full reference: [docs/configuration.md](docs/configuration.md) /
`agentbox.toml(5)`. Copy-paste starting points for common stacks (Node,
Python, Go, .NET, monorepos, air-gapped, VM tier, custom images) are in
[docs/configuration-examples.md](docs/configuration-examples.md).

### A committed config outranks yours, and says so

The workspace layer sits above your user config, so cloning a repository and
running `agentbox` applies configuration you did not write. agentbox lets it
win — that is what layering means — and then refuses to be quiet about it.
Any workspace value that *weakens* a security-relevant key relative to a
lower layer produces a warning on **every invocation**, naming the key, both
values, and the file responsible:

```console
$ agentbox
warning: network.mode: /src/myproject/agentbox.toml lowered this from "proxy"
  to "open" (the built-in default set "proxy"); the workspace value is in
  effect -- pass --network to override it
agentbox: backend vm (tier vm) | egress open | masking filter, 3 path(s) hidden
```

Tightening is silent, because a project asking for a *stronger* box is a
project config doing its job. The keys ranked this way are
`security.min_isolation`, `network.mode`, `security.mask_mode`,
`security.strip_setuid`, `workspace.readonly`, `security.vm.guest_root`, and
the container hardening booleans. Egress allowlists are not ranked — a repo
declaring the registries it needs is the normal case — so read
`config --origin` if you want to know where a domain came from.

## Security model, honestly

Two isolation tiers exist behind one contract: `container` (Docker or
rootless Podman) and `vm` (Kata Containers via Docker, on KVM). They are
**not equivalent**, and agentbox is built around never letting that
difference hide:

- A project declares the weakest tier it accepts (`min_isolation`); if no
  available backend meets it, agentbox exits 69 naming what is missing.
  **No silent downgrade, no warned downgrade** — lowering the floor requires
  `--force-isolation`, which is recorded and warned on every invocation.
- Backend-specific settings are scoped (`[security.container]`,
  `[security.vm]`) and statically validated everywhere.
- `status`, and the banner printed whenever a box starts, always show the
  backend and tier in force.

Universal refusals: no host networking, no host PID namespace, no mounted
container-runtime socket, no unconfined seccomp. Boxes cannot reach each
other's network, state, or mask views.

The full property table, threat model, and documented limitations of
masking are in [docs/security.md](docs/security.md) and
`agentbox-security(7)`. The one-paragraph version: **in scope** — careless
or prompt-injected agents, malicious install scripts, accidental
destruction outside the workspace; **out of scope** — kernel/runtime escape
under the container tier, hypervisor escape, determined targeted attackers.

## Status and roadmap

agentbox is pre-release. Current version: `0.0.1-dev` — nothing has been
published yet, and the config schema may still change.

Versioning is [SemVer](https://semver.org/); what the version number
promises and how each release is checked for breaking changes is documented
in [docs/versioning.md](docs/versioning.md).

| Area | Status |
|---|---|
| CLI contract: dispatch, `--`, sysexits, signal forwarding, verbatim exit codes | ✅ |
| Identity: workspace detection, one box per workspace root | ✅ |
| Config: 4 layers, `--origin`, static backend-scope validation, loud weakening | ✅ |
| Isolation floor: exit 69, no downgrade, `--force-isolation` recorded + warned | ✅ |
| Image: feature digest, generated Dockerfile (uid reclaim, setuid strip, pinned keys) | ✅ |
| Masking: shared gitignore matcher, per-box Layer-0 plan, `mask_mode` | ✅ |
| Network: `off`/`proxy`/`open`, 13 bundles, deny-first, generated squid config | ✅ |
| State: XDG layout, atomic metadata, per-box locking, per-box homes | ✅ |
| Container backend: Docker + rootless Podman, proxy sidecar, no-gateway network | ✅ |
| VM backend: Kata via Docker, same sidecar topology, host-side mask view | ✅ |
| Layer-3 lookup-time filtering (`mask_mode = "filter"`, own share daemon) | ✅ |
| Teardown: `down` keeps the home, `rm` reclaims only what agentbox built | ✅ |
| Man pages | ✅ |
| Podman for the vm tier | 🚧 blocked upstream (see deviations) |
| Proxy credential injection | 🚧 planned |

Deviations, honestly stated:

- **The vm tier is Docker + Kata, and only that.** Podman's VM path is
  libkrun, whose crun handler implements no `exec` callback: a box created
  under it comes up and no agentbox command can ever enter it
  (containers/crun#2090). Rather than offer a runtime that parses, selects,
  creates a box and then cannot be used, agentbox does not offer it — and
  says so when podman is the only thing installed. There is likewise no
  `hypervisor` or `runtime` configuration key; offering a choice agentbox
  cannot honor is what made that mess.
- **A Kata guest cannot use Docker's embedded DNS.** The resolver lives at
  127.0.0.11 inside the network namespace, and a VM guest's loopback is its
  own, so container names do not resolve. The vm tier therefore addresses
  its proxy sidecar by a pinned IP, and `network = "open"` bind-mounts a
  generated `/etc/resolv.conf` carrying the host's real upstream
  nameservers. (`--dns` does not help: on a user-defined network the engine
  still writes 127.0.0.11 and merely redirects the embedded resolver's
  upstream.) In `proxy` mode the guest needs no resolver at all — squid
  resolves on its behalf, which also denies the box a DNS channel of its own.
- The Layer-3 filtered share is delivered by interposing agentbox's own
  FUSE filesystem *underneath* the runtime's virtiofsd (virtiofsd serves
  the filtered mount), not by replacing virtiofsd via Kata's
  `virtio_fs_daemon`, the more obvious integration point. The enforcement
  point is identical — host-side, outside guest reach — and the seam does
  not depend on runtime-specific daemon-path configuration.
- The filtered share needs `/dev/fuse` and a mount route: agentbox running
  as root, or the setuid `fusermount3` helper with `user_allow_other` set
  in `/etc/fuse.conf`, which lets the share daemon run entirely in the
  user's context. Where no route exists, `mask_mode = "auto"` resolves to
  `view` with a warning naming the reason, and an explicit `"filter"` is
  an error. No silent downgrade occurs in either direction.
- The `vm` tier's host-side mask view needs agentbox to run with
  CAP_SYS_ADMIN; without it, mask mounts are expressed in the guest and
  agentbox warns that a guest root process could unmount them.
- A committed workspace config can weaken your security settings; agentbox
  warns on every invocation rather than refusing. See "A committed config
  outranks yours" above.
- VM conformance tests need KVM plus a Kata runtime and run as a separate
  CI job that fails if the suite skips; they are not part of
  `go test ./...` on an ordinary host.
- Container-backend end-to-end tests need a Docker daemon and are not part
  of `go test ./...`; the policy, plan, and state logic they exercise is
  covered at the unit level.

## Building and testing

```console
$ go build ./cmd/agentbox        # Go 1.26, one dependency
$ go test ./...
$ make all                       # fmt-check + vet + build + test
```

The ignore-matcher conformance suite differentially tests against
`git check-ignore` and needs `git` on `PATH`. The real-mount Layer-0 test
requires root or `CAP_SYS_ADMIN` and skips visibly elsewhere; CI runs it in
a privileged job.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: see
[SECURITY.md](SECURITY.md) — please do not open public issues for
vulnerabilities.

Documented behavior is the contract; behavior changes should update the
docs, and divergences belong in the "deviations" list above, not in
silence.

## License

[The Unlicense](LICENSE) — this software is released into the public domain.
