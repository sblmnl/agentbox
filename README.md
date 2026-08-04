# agentbox

> [!WARNING]
> **Experimental and educational — do not use in security-sensitive environments.**
> agentbox is a personal side project, not an audited security tool. It began
> as an idea from a web developer (C#/TypeScript) with **no background in Go or
> in low-level container/VM sandboxing**, and neither the code nor its security
> reasoning has been independently reviewed. Everything below about isolation,
> secret masking, and egress control describes *design intent under active
> development* — **treat it as aspirational, not as a guarantee.** Do not rely
> on agentbox to contain untrusted or malicious code, to protect real secrets,
> or for anything where a sandbox escape would actually matter. Use it to learn
> and experiment, at your own risk. See [docs/security.md](docs/security.md).

Run an agentic coding tool inside an isolated, per-project environment —
declarative config, default-deny egress, host-side secret masking,
disposable named boxes.

```console
$ cd ~/src/myapp
$ agentbox claude
```

That resolves the project root, merges configuration, selects a backend
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
- **Many boxes per project.** Named, listable, resumable environments. Extra
  boxes get their own `git worktree` on their own branch by default, so
  parallel agents never trample your tree or each other's.
- **Boxes are disposable, isolated from each other,** and honest about what
  they guarantee: `agentbox status` always names the backend, isolation
  tier, and mask mode in force.
- **Any agent.** Claude Code is bundled as a first-class citizen, but
  nothing in the data model is vendor-specific.

## Quickstart

```console
$ git clone https://github.com/sblmnl/agentbox && cd agentbox && sudo make install

$ cd ~/src/myapp
$ agentbox init                  # scaffold agentbox.toml + .agentignore
$ agentbox doctor                # preflight: backends, config, remotes
$ agentbox mounts                # what will the agent see, and why?
$ agentbox claude                # run your agent in the box
```

Useful from day one:

```console
$ agentbox --dry-run claude      # print the full plan; change nothing
$ agentbox config --origin       # every key, annotated with the layer that set it
$ agentbox logs --denied         # what did the agent try to reach?
$ agentbox new --name exp        # second box on its own worktree + branch
$ agentbox ls                    # all boxes: backend, tier, tree mode, age
$ agentbox ls --artifacts        # ...and what each is holding, plus what nothing holds
```

Reclaiming the disk it all sits on:

```console
$ agentbox prune                 # what can be reclaimed; removes nothing
$ agentbox prune --apply         # reclaim it
$ agentbox prune --apply --boxes --running --state --images   # tear it all down
```

`--boxes` is what makes a live box a candidate at all, and it widens in named
steps: `--boxes` takes stopped boxes, `--running` also takes running ones,
`--state` also takes their persistent homes. A branch is never deleted at any
combination of flags, and boxes prune left alone are named at the end of the
run.

Requirements: Linux, Docker (Compose v2) or rootless Podman, `git` for
worktree tree mode, and Go to build. A single static binary with one
dependency (`BurntSushi/toml`). agentbox is **build-from-source only** —
there are no published binaries or packages. Build steps and runtime setup
for each tier are in [docs/install.md](docs/install.md).

## Configuration

`agentbox.toml` is committed, reviewable, and layered (system → user →
workspace → profile → env → flags), with `config --origin` attribution and
static validation — unknown keys and backend-scoped keys in the wrong place
are hard errors on every machine, not just where they would apply.

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

Because the workspace config is committed, cloning a repo and running
`agentbox` would execute configuration you did not write. Host-side
`[hooks]` and `[[workspace.mounts]]` are therefore **refused until you
review the file and run `agentbox trust`** (direnv-style; any edit
invalidates trust).

## Security model, honestly

Two isolation tiers exist behind one contract: `container` (Docker or
rootless Podman) and `vm` (Kata Containers via docker, or libkrun via
podman, on KVM). They are **not equivalent**, and agentbox is built around
never letting that difference hide:

- A project declares the weakest tier it accepts (`min_isolation`); if no
  available backend meets it, agentbox exits 69 naming what is missing.
  **No silent downgrade, no warned downgrade** — lowering the floor requires
  `--force-isolation`, which is recorded and warned on every invocation.
- Backend-specific settings are scoped (`[security.container]`,
  `[security.vm]`) and statically validated everywhere.
- `status` and `ls` always show each box's backend and tier.

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

agentbox is feature-complete through the Layer-3 filtered share; proxy
credential injection is the main piece still to come. Current version:
`0.0.1-dev` — nothing has been published yet; this is the pre-release
development version heading toward the first tagged release, and the config
schema may still change.

Versioning is [SemVer](https://semver.org/); what the version number
promises and how each release is checked for breaking changes is documented
in [docs/versioning.md](docs/versioning.md).

| Area | Status |
|---|---|
| CLI contract: dispatch, `--`, sysexits, signal forwarding, verbatim exit codes | ✅ |
| Identity: workspace detection, project/box two-level identity, ordinal aliases | ✅ |
| Tree modes: `shared` / `worktree` / `copy` / `auto`, branch-preserving `rm` | ✅ |
| Config: 7 layers, `--origin`, `extends`, profiles, static backend-scope validation | ✅ |
| Isolation floor: exit 69, no downgrade, `--force-isolation` recorded + warned | ✅ |
| Image: feature digest, generated Dockerfile (uid reclaim, setuid strip, pinned keys) | ✅ |
| Masking: shared gitignore matcher, per-box Layer-0 plan, `mask_mode` | ✅ |
| Network: `none`/`proxy`/`open`, 12 bundles, deny-first, generated squid config | ✅ |
| State: XDG layout, atomic metadata, two-level locking, per-box homes | ✅ |
| Container backend: Docker + rootless Podman, proxy sidecar, no-gateway network | ✅ |
| Governance: `max_boxes`, `[limits]`, idle stop (never remove) | ✅ |
| Unified view: `ls`/`status --artifacts`, expected vs. actual, unclaimed set | ✅ |
| Bulk teardown: `prune --boxes/--running/--state`, branches never deleted | ✅ |
| Workspace-config trust (TOFU for `[hooks]` / mounts) | ✅ |
| Man pages, shell completions (bash/zsh/fish) | ✅ |
| VM backend: Kata (docker) / libkrun (podman), per-box selection, host proxy daemon reached over vsock, host-side mask view | ✅ |
| Layer-3 lookup-time filtering (`mask_mode = "filter"`, own share daemon) | ✅ |
| Proxy credential injection | 🚧 planned |

Deviations, honestly stated:

- The Layer-3 filtered share is delivered by interposing agentbox's own
  FUSE filesystem *underneath* the runtime's virtiofsd (virtiofsd serves
  the filtered mount), not by replacing virtiofsd via Kata's
  `virtio_fs_daemon`, the more obvious integration point. The enforcement point is
  identical — host-side, outside guest reach — and the seam does not
  depend on runtime-specific daemon-path configuration.
- The filtered share needs `/dev/fuse` and a mount route: agentbox running
  as root, or the setuid `fusermount3` helper with `user_allow_other` set
  in `/etc/fuse.conf`, which lets the share daemon run entirely in the
  user's context. `user_allow_other` is required on the unprivileged route
  even where the runtime's virtiofs server shares the user's uid and would
  not strictly need it — refusing up front beats a box that starts and then
  fails opaquely. Where no route exists, `mask_mode = "auto"` resolves to
  `view` with a warning naming the reason, and an explicit `"filter"` is
  an error. `agentbox doctor` reports which way `auto` resolves; no silent
  downgrade occurs in either direction.
- The `vm` tier's host-side mask view needs agentbox to run with
  CAP_SYS_ADMIN; without it, mask mounts are expressed in the guest and
  agentbox warns that a guest root process could unmount them.
- VM conformance tests need KVM plus a kata/krun runtime and run as a
  separate CI job that fails if the suite skips; they are not part of
  `go test ./...` on an ordinary host.
- `agentbox allow` rewrites the workspace TOML structurally and does not
  preserve comments (it says so when it runs).
- Container-backend end-to-end tests need a Docker daemon and are not part
  of `go test ./...`; the policy, plan, and state logic they exercise is
  covered at the unit level.

## Building and testing

```console
$ go build ./cmd/agentbox        # Go ≥ 1.22, one dependency
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
