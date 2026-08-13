# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

agentbox runs an agentic coding tool inside an isolated, per-project environment: it resolves the workspace root, merges layered config, selects a backend meeting the project's isolation floor, builds a toolchain image, constructs a masked view of the workspace that hides secrets, starts a default-deny egress proxy, and execs the agent. Read `README.md`, `docs/security.md`, and `docs/configuration.md` for the user-facing contract.

## Build, test, lint

```console
go build -trimpath ./cmd/agentbox   # single static binary, one dep (BurntSushi/toml)
go test ./...
make all                            # fmt-check + vet + build + test (the pre-PR gate)
go test ./internal/config/          # one package
go test -run TestName ./internal/config/   # one test
```

- Toolchain is pinned by `go.mod` (Go 1.26). `gofmt` clean and `go vet` clean are enforced in CI; run `make fmt-check vet` before finishing.
- Some suites are **deliberately excluded** from `go test ./...` and run as dedicated CI jobs that **fail if they skip instead of run** (a green build that silently omitted them is the failure mode those jobs prevent):
  - `make test-privileged` — the Layer-0 real-mount test (`TestLayer0RealMounts`), needs root/`CAP_SYS_ADMIN`.
  - `test/vmconformance/` — needs KVM + a Kata runtime; gated behind `AGENTBOX_VM_CONFORMANCE=1` and `AGENTBOX_BIN`.
  - Container/VM end-to-end tests need a live Docker daemon; the policy/plan/state logic they'd exercise is covered at the unit level instead.
- The ignore-matcher conformance suite differentially tests against `git check-ignore`, so `git` must be on `PATH`.
- `make man-lint` (needs mandoc/groff) lints the man pages.

## Architecture

Everything flows through a single build-a-plan-then-enact pipeline. **Building a plan never creates or starts anything** — `--dry-run` and `config` produce the same `Plan` the enacting commands do. `--dry-run --json` is the inspection surface: it publishes the full mask set, the resolved egress policy, and the selected backend, and its JSON shape is part of the documented contract.

**Entry & dispatch** (`cmd/agentbox/main.go`): hand-rolled flag parser, then *interpretation* — the first non-flag arg that is in the closed `reserved` subcommand set dispatches to a `Cmd*` method; anything else (or after `--`) is a command to run *inside the box*. Adding a reserved subcommand is a breaking CLI change. `fsd` is a hidden entry point (the mask-filter share daemon), intercepted before parsing. agentbox owns its own exit codes per `sysexits.h`: **64** usage, **69** isolation floor unsatisfiable, **78** invalid config; the in-box command's exit code is otherwise passed through verbatim.

**One box per workspace root.** The workspace root *is* the box's identity — there is no instance name, no default-box pointer, and no `-n`. A project gets a second box by getting a second root: `git worktree add ../feature` is a different directory, so it gets its own box and its own branch for free. This is why there are no tree modes and no branch lifecycle to manage.

**`internal/app`** wires subsystems into commands. `Resolve()` (`app.go`) is the front door for every command: workspace detection → config load → flag overlay, producing a `Ctx`. `plan.go` turns a `Ctx` into a `Plan` (box identity, backend availability, image resolution, mask set, network policy, guest workdir). `commands.go`/`lifecycle.go`/`inspect.go`/`scaffold.go` are the `Cmd*` methods.

**`internal/config`** — 4 layers merged lowest-to-highest: built-in → user → workspace → flags (`load.go`). `--origin` attributes every key to the layer that set it. Static validation is total: unknown keys and backend-scoped keys placed in the wrong section (`[security.container]` vs `[security.vm]`) are **hard errors on every machine**, not just where they'd apply.

`weaken.go` is the answer to "a committed workspace config outranks the user's own". The merge is ordinary last-writer-wins, but any workspace value that *loosens* a ranked security key relative to a lower layer produces a warning naming the key, both values, and the file — on every invocation. Adding a security-relevant key with ordered values means adding it to `strictness`.

**`internal/backend`** — defines the isolation *contract* both backends implement (`backend.go`, `BoxSpec`), plus the selection algorithm, expressed with no Compose YAML or hypervisor config leaking in. Two tiers: `container` (Docker / rootless Podman, `container.go`) and `vm` (Kata via Docker, `vm.go`). Tiers are **not equivalent and never silently downgraded**: a project declares `min_isolation`; if nothing meets it, exit 69 naming what's missing. Lowering the floor requires `--force-isolation`, which is recorded in box metadata and warned on every invocation.

Both tiers use the **same egress topology**: a per-box `--internal` bridge plus a squid sidecar that straddles a second, routable network. Two facts about Kata drive the differences that remain, and both were established by experiment, not assumption:

- A Kata guest **can** reach a sibling container over an ordinary bridge, by IP.
- It **cannot** reach Docker's embedded DNS resolver, which lives at 127.0.0.11 in the network namespace while the guest's loopback is its own. So the vm tier addresses its sidecar by a **pinned IP** rather than by container name, and `network = "open"` bind-mounts a **generated `/etc/resolv.conf`** carrying the host's real upstream nameservers. `--dns` does not help: on a user-defined network the engine still writes 127.0.0.11 and only redirects the embedded resolver's upstream.

In proxy mode the guest needs no resolver at all — squid resolves on its behalf, which also denies the box a DNS channel of its own.

**`internal/mask`** — secret hiding, enforced host-side. `ignore.go`'s matcher (differentially tested against `git check-ignore`) and the mask-set computation are **shared, single-implementation code**: do not fork or duplicate them — a second implementation doubles the surface for a silent failure to mask a secret. `layer0.go` is the per-box mount plan. Modes: `view` and `filter` (Layer-3, vm tier only, served by `internal/share` — agentbox's own FUSE share daemon, spawned as the hidden `fsd` subcommand). `auto` under the vm tier resolves to `filter` where the seam is deliverable (root + `/dev/fuse`), else to `view` **with a warning**; an explicit `filter` that cannot be delivered is a config error naming why. The filter daemon compiles patterns from contents frozen at spawn — never re-read from the guest-writable tree.

**`internal/netpol`** — default-deny egress. `netpol.go` compiles bundles + allowlist into a `Policy` and generates squid config. Modes are `off`, `proxy`, `open`. Widening a **bundle** widens every user's egress and must be justified in the PR.

**`internal/state`** — XDG layout under `$XDG_STATE_HOME/agentbox` (`state.go`), atomic box metadata, one lock per box (`lock.go`). `BoxMeta` freezes config/image/mask digests at creation and recomputes+compares them on every later invocation to detect drift.

**Supporting packages**: `internal/identity` (workspace detection, the workspace-rooted box key), `internal/image` (feature-digest-keyed generated Dockerfile), `internal/workspace` (root detection).

## Invariants (the review bar is stricter than usual here)

- **No silent weakening.** Anything reducing an enforced property — masking, egress policy, isolation floor, box separation — must be *loud*: an error, or a warning on every invocation. This is the criterion applied most strictly in review; tests for masking/egress must cover the *refusal* path, not just the happy path. A workspace config is permitted to weaken; it is not permitted to do so quietly.
- **Reclaim only what agentbox made.** `rm` removes a built image but never a pinned `[image].ref` — the user owns that one. `BoxMeta.ImageBuilt` is what distinguishes them.
- **Documented behavior is the contract.** A behavior change must update the README, the relevant `docs/*.md`, and the man pages under `docs/man/`. Intentional divergences go in the README "deviations" list — silence about them is not acceptable.
- Diagnostics go to **stderr**; **stdout belongs to the in-box command**.

## Traps that have already bitten

- **`--tmpfs` inherits the image directory's mode.** Docker only defaults a tmpfs to 1777 when the mountpoint does *not* exist in the image. `/run`, `/var/log/squid` and `/var/spool/squid` all exist in `ubuntu/squid`, so without an explicit `mode=1777` the sidecar (uid 31337, no capabilities) cannot write its pid file and squid exits FATAL before binding — presenting as a network fault, not a dead proxy.
- **The generated `squid.conf` must be world-readable.** The sidecar bind-mounts it as uid 31337; `0600` owned by the invoking user makes squid die at startup.
- **`umount(2)` checks `CAP_SYS_ADMIN` before it checks whether anything is mounted**, so an unprivileged unmount of a plain directory returns `EPERM`, not `EINVAL`. Teardown must test `IsMountPoint` first or it fails on every filter-mode box.
- **`/dev/tcp` is a bash builtin**, and the box's `/bin/sh` is dash. A reachability probe written for `sh` reports every healthy box as unreachable.
- **Subnet allocation is check-then-act** against the engine's network list, which agentbox does not own. Two boxes starting at once can claim the same `/24`; the retry must *exclude* the subnet that lost, because re-surveying alone can keep picking it.
